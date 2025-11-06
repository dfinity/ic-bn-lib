use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use http::Request;
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use ic_bn_lib_common::{
    traits::acme::{AcmeCertificateClient, TokenManager},
    types::{
        acme::{AcmeUrl, Error},
        tls::AcmeCert,
    },
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationHandle, AuthorizationStatus, BodyWrapper,
    BytesResponse, ChallengeHandle, ChallengeType, Error as AcmeError,
    HttpClient as HttpClientTrait, Identifier, NewAccount, NewOrder, Order, OrderStatus,
    RetryPolicy, RevocationRequest,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tracing::{debug, instrument};

use crate::{
    RetryError, retry_async,
    tls::{prepare_client_config, verify::NoopServerCertVerifier},
};

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

#[async_trait]
impl AcmeCertificateClient for Client {
    /// Issue the certificate with provided names and an optional private key.
    /// Key must be in PEM format, if it's not provided - new one will be generated.
    #[instrument(level = "debug", skip_all, fields(names = %names.join(", ")))]
    async fn issue(
        &self,
        names: Vec<String>,
        private_key: Option<Vec<u8>>,
    ) -> Result<AcmeCert, Error> {
        self.issue_inner(&names, private_key).await
    }

    /// Revokes the certificate according to the provided request
    async fn revoke<'a>(&self, request: &RevocationRequest<'a>) -> Result<(), Error> {
        self.account
            .revoke(request)
            .await
            .map_err(|e| Error::Generic(e.into()))
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
    async fn poll_token(&self, id: &str, token: &str) -> Result<(), Error> {
        retry_async! {
            async {
                self.token_manager
                    .verify(id, token)
                    .await
                    .map_err(RetryError::Transient)
            },
            self.opts.token_timeout
        }
        .map_err(Error::UnableToVerifyChallengeToken)
    }

    fn authorization_extract_challenge<'a>(
        &self,
        authz: &'a mut AuthorizationHandle<'a>,
    ) -> Result<Option<(String, String, ChallengeHandle<'a>)>, Error> {
        match authz.status {
            AuthorizationStatus::Valid => {
                debug!("Authorization already valid");
                return Ok(None);
            }

            AuthorizationStatus::Pending => {}
            _ => {
                return Err(Error::UnexpectedAuthorizationStatus(authz.status));
            }
        }

        // Get the challenge
        let challenge = authz
            .challenge(self.opts.challenge.clone())
            .ok_or_else(|| Error::NoChallengeFound(self.opts.challenge.clone()))?;

        // Get an identifier & a token from the challenge
        let identifier = challenge.identifier().identifier;

        // Currently we support DNS only.
        // TODO add IP address too?
        let id = match identifier {
            Identifier::Dns(v) => v.clone(),
            _ => return Err(Error::UnsupportedIdentifierType(identifier.clone())),
        };
        let token = challenge.key_authorization().dns_value();

        Ok(Some((id, token, challenge)))
    }

    /// Process a single challenge
    #[instrument(level = "debug", skip_all, fields(id = id))]
    async fn process_challenge(
        &self,
        id: String,
        token: String,
        mut challenge: ChallengeHandle<'_>,
    ) -> Result<(), Error> {
        debug!("Got id '{id}' and token '{token}', setting it");

        // Set token on the identifier
        self.token_manager
            .set(&id, &token)
            .await
            .map_err(Error::UnableToSetChallengeToken)?;

        debug!("Token set, polling to verify");

        // Verify that the token is correcly set
        self.poll_token(&id, &token).await?;

        debug!("Token verified, setting challenge ready");

        // Set the challenge as ready
        challenge
            .set_ready()
            .await
            .map_err(Error::UnableToSetChallengeReady)?;

        debug!("Challenge set as ready");
        Ok(())
    }

    /// Iterates over authorizations in the order and tries to fulfill them.
    /// Returns the list of IDs that are later used in the cleanup.
    #[instrument(level = "debug", skip_all)]
    async fn process_authorizations(&self, order: &mut Order) -> Result<(), Error> {
        let mut authorizations = order.authorizations();

        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(Error::UnableToGetAuthorizations)?;
            // Extract id, token & challenge from an authorization
            let Some((id, token, challenge)) = self.authorization_extract_challenge(&mut authz)?
            else {
                continue;
            };

            self.process_challenge(id, token, challenge).await?;
        }

        Ok(())
    }

    /// Cleans up the tokens after issuance using authorization IDs
    #[instrument(level = "debug", skip_all, fields(ids = %auth_ids.join(", ")))]
    async fn cleanup(&self, auth_ids: &[String]) -> Result<(), Error> {
        debug!(
            "Cleaning up the authorization tokens for ids: {}",
            auth_ids.join(", ")
        );

        for id in auth_ids {
            debug!("Unsetting token for id: '{id}'");

            self.token_manager
                .unset(id)
                .await
                .map_err(Error::UnableToUnsetChallengeToken)?;
        }

        Ok(())
    }

    async fn get_authorization_ids(&self, order: &mut Order) -> Result<Vec<String>, Error> {
        let mut auth_ids = vec![];
        let mut identifiers_stream = order.identifiers();
        while let Some(id) = identifiers_stream.next().await {
            let id = id.map_err(Error::UnableToGetAuthorizations)?.to_string();
            if !auth_ids.contains(&id) {
                auth_ids.push(id.to_string());
            }
        }

        Ok(auth_ids)
    }

    #[instrument(level = "debug", skip_all)]
    async fn issue_inner(
        &self,
        names: &[String],
        private_key: Option<Vec<u8>>,
    ) -> Result<AcmeCert, Error> {
        // Prepare order identifiers
        let ids = names
            .iter()
            .map(|x| Identifier::Dns(x.to_string()))
            .collect::<Vec<_>>();

        debug!("Preparing the order");

        // Prepare the order
        let mut order = self.prepare_order(ids).await?;

        // Get auth ids and clean them up
        let auth_ids = self.get_authorization_ids(&mut order).await?;
        self.cleanup(&auth_ids).await?;

        debug!(
            "Order obtained (status: {:?}), processing authorizations",
            order.state().status
        );

        // Process authorizations and fulfill their challenges
        self.process_authorizations(&mut order).await?;

        debug!("Authorizations processed, waiting for the order to reach Ready state");

        let retry_policy = RetryPolicy::new().timeout(self.opts.order_timeout);

        // Wait until the order reaches Ready state or becomes invalid
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(Error::OrderUnableToReachReadyStatus)?;

        debug!("Order reached Ready state, creating CSR");

        // Prepare the signing request
        let mut params =
            CertificateParams::new(names).map_err(Error::UnableToGenerateCertificateParams)?;
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
        debug!("Finalizing the order");
        order
            .finalize_csr(csr.der())
            .await
            .map_err(Error::UnableToFinalizeOrder)?;

        debug!("Order is finalized, polling for the certificate");

        // Retrieve the certificate.
        // It polls until the order is Valid, Invalid or times out.
        let cert = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(Error::UnableToGetCertificate)?;

        debug!("Certificate obtained successfully, cleaning up");
        self.cleanup(&auth_ids).await?;

        Ok(AcmeCert {
            cert: cert.as_bytes().to_vec(),
            key: key_pair.serialize_pem().as_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use instant_acme::{Problem, RevocationReason};

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

    #[test]
    fn test_rate_limited_detection() {
        // An example of rate limiting error from Let's Encrypt (normally both type and status are present)
        let problem = Problem {
            r#type: Some("urn:ietf:params:acme:error:rateLimited".to_string()),
            detail: Some("too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2025-08-30 19:01:33 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers".to_string()),
            status: Some(429),
            subproblems: vec![],
        };

        let client_error = Error::UnableToCreateOrder(AcmeError::Api(problem));

        assert!(
            client_error.rate_limited(),
            "Detect rate limiting from type"
        );
    }
}
