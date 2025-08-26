use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use http::Request;
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    Error as AcmeError, HttpClient as HttpClientTrait, Identifier, NewAccount, NewOrder, Order,
    OrderStatus, RetryPolicy, RevocationRequest,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tracing::debug;

use crate::{
    RetryError, retry_async,
    tls::{acme::AcmeUrl, prepare_client_config, verify::NoopServerCertVerifier},
};

use super::TokenManager;

/// Error thet ACME client returns
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unexpected authorization status: {0:?}")]
    UnexpectedAuthorizationStatus(AuthorizationStatus),
    #[error("Unexpected order status: {0:?}")]
    UnexpectedOrderStatus(OrderStatus),
    #[error("Unable to set challenge token: {0}")]
    UnableToSetChallengeToken(anyhow::Error),
    #[error("Unable to verify challenge token: {0}")]
    UnableToVerifyChallengeToken(anyhow::Error),
    #[error("Unable to create order: {0}")]
    UnableToCreateOrder(AcmeError),
    #[error("Unable to get authorizations: {0}")]
    UnableToGetAuthorizations(AcmeError),
    #[error("Unable to set challenge as ready: {0}")]
    UnableToSetChallengeReady(AcmeError),
    #[error("Unable to finalize order: {0}")]
    UnableToFinalizeOrder(AcmeError),
    #[error("Unable to get certificate: {0}")]
    UnableToGetCertificate(AcmeError),
    #[error("Unable to generate certificate params: {0}")]
    UnableToGenerateCertificateParams(rcgen::Error),
    #[error("Unable to generate private key: {0}")]
    UnableToGeneratePrivateKey(rcgen::Error),
    #[error("Unable to parse private key: {0}")]
    UnableToParsePrivateKey(rcgen::Error),
    #[error("Unable to create CSR: {0}")]
    UnableToCreateCSR(rcgen::Error),
    #[error("No challenge found: {0:?}")]
    NoChallengeFound(ChallengeType),
    #[error("Unsupported identifier type: {0:?}")]
    UnsupportedIdentifierType(Identifier),
    #[error("Order unable to reach ready status: {0}")]
    OrderUnableToReachReadyStatus(AcmeError),
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

impl Error {
    pub fn rate_limited(&self) -> bool {
        let acme_error = match self {
            Self::UnableToCreateOrder(v) => v,
            Self::UnableToGetAuthorizations(v) => v,
            Self::UnableToSetChallengeReady(v) => v,
            Self::UnableToFinalizeOrder(v) => v,
            Self::UnableToGetCertificate(v) => v,
            _ => return false,
        };

        if let AcmeError::Api(v) = acme_error {
            return v.r#type.as_deref() == Some("rateLimited");
        }

        false
    }
}

/// Certificate and private key pair
pub struct Cert {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

struct HttpClient(HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>);

impl HttpClient {
    /// Create a new client
    fn new(insecure_tls: bool) -> Self {
        let mut tls_config =
            prepare_client_config(&[&rustls::version::TLS13, &rustls::version::TLS12]);

        // Hyper doesn't like when ALPN is set
        tls_config.alpn_protocols = vec![];

        if insecure_tls {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoopServerCertVerifier::default()));
        }

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        Self(HyperClient::builder(TokioExecutor::new()).build(connector))
    }
}

impl HttpClientTrait for HttpClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        let fut = self.0.request(req);

        Box::pin(async move {
            match fut.await {
                Ok(rsp) => Ok(BytesResponse::from(rsp)),
                Err(e) => Err(AcmeError::Other(Box::new(e))),
            }
        })
    }
}

/// Client options
pub struct Opts {
    pub challenge: ChallengeType,
    pub url: AcmeUrl,
    pub order_timeout: Duration,
    pub token_timeout: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            challenge: ChallengeType::Dns01,
            url: AcmeUrl::LetsEncryptStaging,
            order_timeout: Duration::from_secs(60),
            token_timeout: Duration::from_secs(60),
        }
    }
}

/// Builder that builds a Client
pub struct ClientBuilder {
    opts: Opts,
    account: Option<Account>,
    insecure_tls: bool,
    token_manager: Option<Arc<dyn TokenManager>>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ClientBuilder {
    /// Create a new builder, optionally with an insecure TLS
    pub fn new(insecure_tls: bool) -> Self {
        Self {
            opts: Opts::default(),
            account: None,
            insecure_tls,
            token_manager: None,
        }
    }

    /// Create the account with the provided contact
    pub async fn create_account(
        mut self,
        contact: &str,
    ) -> Result<(Self, AccountCredentials), AcmeError> {
        let (account, creds) =
            Account::builder_with_http(Box::new(HttpClient::new(self.insecure_tls)))
                .create(
                    &NewAccount {
                        contact: &[contact],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    self.opts.url.to_string(),
                    None,
                )
                .await?;

        self.account = Some(account);
        Ok((self, creds))
    }

    /// Restore the account from the provided credentials
    pub async fn load_account(
        mut self,
        credentials: AccountCredentials,
    ) -> Result<Self, AcmeError> {
        let account = Account::builder_with_http(Box::new(HttpClient::new(self.insecure_tls)))
            .from_credentials(credentials)
            .await?;

        self.account = Some(account);
        Ok(self)
    }

    /// Build the client
    pub async fn build(self) -> Result<Client, Error> {
        let account = self
            .account
            .context("no account has been created or loaded")?;
        let token_manager = self.token_manager.context("no token manager provided")?;

        Ok(Client::new(self.opts, account, token_manager))
    }

    /// Use the provided token manager
    pub fn with_token_manager(mut self, token_manager: Arc<dyn TokenManager>) -> Self {
        self.token_manager = Some(token_manager);
        self
    }

    /// Set the order timeout. Default is 60s.
    pub const fn with_order_timeout(mut self, order_timeout: Duration) -> Self {
        self.opts.order_timeout = order_timeout;
        self
    }

    /// Set the token timeout. Default is 60s.
    pub const fn with_token_timeout(mut self, token_timeout: Duration) -> Self {
        self.opts.token_timeout = token_timeout;
        self
    }

    /// Set the ACME URL. Default is LetsEncrypt Staging.
    pub fn with_acme_url(mut self, url: AcmeUrl) -> Self {
        self.opts.url = url;
        self
    }

    /// Set the challenge type. Default is DNS-01.
    pub fn with_challenge(mut self, challenge: ChallengeType) -> Self {
        self.opts.challenge = challenge;
        self
    }
}

/// ACME client trait to issue and revoke certificates
#[async_trait]
pub trait AcmeCertificateClient {
    /// Issue the certificate with provided names and an optional private key.
    async fn issue(
        &self,
        names: impl IntoIterator<Item = impl AsRef<str>> + Send,
        private_key: Option<Vec<u8>>,
    ) -> Result<Cert, Error>;

    /// Revoke the certificate according to the provided request
    async fn revoke(&self, request: &RevocationRequest<'_>) -> Result<(), Error>;
}

#[async_trait]
impl AcmeCertificateClient for Client {
    /// Issue the certificate with provided names and an optional private key.
    /// Key must be in PEM format, if it's not provided - new one will be generated.
    async fn issue(
        &self,
        names: impl IntoIterator<Item = impl AsRef<str>> + Send,
        private_key: Option<Vec<u8>>,
    ) -> Result<Cert, Error> {
        // Convert to internal format
        let names: Vec<String> = names.into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();

        // Pre-cleanup: attempt to remove all existing tokens for the given names.
        // This ensures a clean state before issuance begins.
        // Treat cleanup failures as non-critical.
        let _ = self.cleanup(&names).await;

        // Try to issue the certificate using the ACME protocol
        let res = self.issue_inner(&names, private_key).await;

        debug!("ACME: Cleaning up");

        // Post-cleanup
        // Treat cleanup failures as non-critical.
        let _ = self.cleanup(&names).await;

        res.map(|(_, cert)| cert)
    }

    /// Revokes the certificate according to the provided request
    async fn revoke(&self, request: &RevocationRequest<'_>) -> Result<(), Error> {
        self.account.revoke(request).await.map_err(|e| Error::Generic(e.into()))
    }
}

/// Generic ACME client that is using TokenManager to set a challenge token
#[derive(derive_new::new)]
pub struct Client {
    opts: Opts,
    account: Account,
    token_manager: Arc<dyn TokenManager>,
}

impl Client {
    /// Creates or retrieves an order for given ids
    async fn prepare_order(&self, ids: Vec<Identifier>) -> Result<Order, Error> {
        debug!("ACME: Order identifiers: {:?}", ids);

        let mut order = self
            .account
            .new_order(&NewOrder::new(&ids))
            .await
            .map_err(Error::UnableToCreateOrder)?;

        let status = order.state().status;

        if ![OrderStatus::Pending, OrderStatus::Ready].contains(&status) {
            return Err(Error::UnexpectedOrderStatus(status));
        }

        Ok(order)
    }

    /// Poll the token manager to verify if the token was correctly set
    async fn poll_token(&self, id: &str, token: &str) -> Result<(), anyhow::Error> {
        retry_async! {
            async {
                self.token_manager
                    .verify(id, token)
                    .await
                    .map_err(RetryError::Transient)
            },
            self.opts.token_timeout
        }
    }

    /// Iterates over authorizations in the order and tries to fulfill them.
    /// Returns the list of IDs that are later used in the cleanup.
    async fn process_authorizations(&self, order: &mut Order) -> Result<Vec<String>, Error> {
        let mut authorizations = order.authorizations();

        let mut ids = vec![];
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(Error::UnableToGetAuthorizations)?;

            match authz.status {
                AuthorizationStatus::Valid => {
                    debug!(
                        "ACME: Authorization '{}' is already valid",
                        authz.identifier()
                    );
                    continue;
                }
                AuthorizationStatus::Pending => {}
                _ => {
                    return Err(Error::UnexpectedAuthorizationStatus(authz.status));
                }
            }

            // Get the challenge
            let mut challenge = authz
                .challenge(self.opts.challenge.clone())
                .ok_or_else(|| Error::NoChallengeFound(self.opts.challenge.clone()))?;

            // Get the identifier & token from the challenge
            let identifier = challenge.identifier().identifier;

            let id = match identifier {
                Identifier::Dns(v) => v.clone(),
                _ => return Err(Error::UnsupportedIdentifierType(identifier.clone())),
            };
            let token = challenge.key_authorization().dns_value();

            // Set id to the token
            self.token_manager
                .set(&id, &token)
                .await
                .map_err(Error::UnableToSetChallengeToken)?;

            // Verify that the token is correcly set
            self.poll_token(&id, &token)
                .await
                .map_err(Error::UnableToVerifyChallengeToken)?;

            // Set the challenge as ready
            challenge
                .set_ready()
                .await
                .map_err(Error::UnableToSetChallengeReady)?;

            debug!("ACME: token '{token}' for challenge id '{id}' set");
            ids.push(id);
        }

        Ok(ids)
    }

    /// Cleans up the tokens after issuance
    async fn cleanup(&self, names: &Vec<String>) -> Result<(), Error> {
        for id in names {
            self.token_manager.unset(id).await?;
        }

        Ok(())
    }

    async fn issue_inner(
        &self,
        names: &Vec<String>,
        private_key: Option<Vec<u8>>,
    ) -> Result<(Vec<String>, Cert), Error> {
        // Prepare order identifiers
        let ids = names
            .iter()
            .map(|x| Identifier::Dns(x.to_string()))
            .collect::<Vec<_>>();

        // Prepare the order
        let mut order = self.prepare_order(ids).await?;

        debug!(
            "ACME: Order for names [{}] obtained (status: '{:?}')",
            names.join(", "),
            order.state().status
        );

        // Process authorizations and fulfill their challenges
        let auth_ids = self.process_authorizations(&mut order).await?;

        debug!("ACME: Authorizations processed");

        let retry_policy = RetryPolicy::new().timeout(self.opts.order_timeout);

        // Wait until the order reaches Ready state or becomes invalid
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(Error::OrderUnableToReachReadyStatus)?;

        debug!(
            "ACME: Order reached 'Ready' status, creating CSR with SANs: {:?}",
            names
        );

        // Prepare the signing request
        let mut params = CertificateParams::new(names.clone())
            .map_err(Error::UnableToGenerateCertificateParams)?;
        params.distinguished_name = DistinguishedName::new();

        // Parse or create the private key
        let key_pair = if let Some(v) = private_key {
            KeyPair::from_pem(&String::from_utf8_lossy(&v))
                .map_err(Error::UnableToParsePrivateKey)?
        } else {
            KeyPair::generate().map_err(Error::UnableToGeneratePrivateKey)?
        };

        let csr = params
            .serialize_request(&key_pair)
            .map_err(Error::UnableToCreateCSR)?;

        // Issue the certificate
        debug!("ACME: Finalizing the order");
        order
            .finalize_csr(csr.der())
            .await
            .map_err(Error::UnableToFinalizeOrder)?;

        debug!("ACME: Order is finalized, requesting the certificate");

        // Retrieve the certificate.
        // It polls until the order is Valid, Invalid or times out.
        let cert = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(Error::UnableToGetCertificate)?;

        debug!("ACME: Certificate obtained successfully");

        Ok((
            auth_ids,
            Cert {
                cert: cert.as_bytes().to_vec(),
                key: key_pair.serialize_pem().as_bytes().to_vec(),
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use instant_acme::RevocationReason;

    use crate::{
        tests::pebble::{Env, dns::TokenManagerPebble},
        tls::pem_convert_to_rustls,
    };

    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_acme_client() {
        let pebble_env = Env::new().await;

        let tm = Arc::new(TokenManagerPebble::new(
            format!("http://{}", pebble_env.addr_dns_management())
                .parse()
                .unwrap(),
        ));

        let builder = ClientBuilder::new(true)
            .with_acme_url(AcmeUrl::Custom(
                format!("https://{}/dir", pebble_env.addr_acme())
                    .parse()
                    .unwrap(),
            ))
            .with_token_manager(tm);

        let (builder, _) = builder.create_account("mailto:foo@bar.com").await.unwrap();
        let cli = builder.build().await.unwrap();

        let cert = cli
            .issue(vec!["foo".to_string(), "*.foo".to_string()], None)
            .await
            .unwrap();

        let cert = pem_convert_to_rustls(&cert.key, &cert.cert).unwrap();
        cli.revoke(&RevocationRequest {
            certificate: cert.end_entity_cert().unwrap(),
            reason: Some(RevocationReason::Superseded),
        })
        .await
        .unwrap();
    }
}
