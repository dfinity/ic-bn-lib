use rustls::{
    DigitallySignedStruct,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        WebPkiSupportedAlgorithms, aws_lc_rs, verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Certificate verifier for rustls that accepts any certificate w/o verification.
/// Should only be used for benchmark/test purposes.
#[derive(Debug)]
pub struct NoopServerCertVerifier(WebPkiSupportedAlgorithms);

impl Default for NoopServerCertVerifier {
    fn default() -> Self {
        Self(aws_lc_rs::default_provider().signature_verification_algorithms)
    }
}

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use rustls::{
        RootCertStore, SignatureScheme, client::WebPkiServerVerifier, internal::msgs::codec::Codec,
    };

    use super::*;
    use crate::{
        tests::{TEST_CERT_1, TEST_CERT_2, TEST_KEY_1, TEST_KEY_2},
        tls::pem_convert_to_rustls,
    };

    /// Some point inside the validity period of the test certificates
    const NOW: u64 = 1_700_000_000;

    fn unix_time(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    /// Builds a `DigitallySignedStruct` by encoding & parsing it back,
    /// since its constructor is crate-private in Rustls.
    fn dss(scheme: SignatureScheme, sig: &[u8]) -> DigitallySignedStruct {
        let mut buf = scheme.to_array().to_vec();
        buf.extend_from_slice(&u16::try_from(sig.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(sig);
        DigitallySignedStruct::read_bytes(&buf).unwrap()
    }

    /// Returns the leaf certificate & a signature over `msg` made with the
    /// matching private key using the given scheme.
    fn sign(
        key: &str,
        cert: &str,
        scheme: SignatureScheme,
        msg: &[u8],
    ) -> (CertificateDer<'static>, Vec<u8>) {
        let ck = pem_convert_to_rustls(key.as_bytes(), cert.as_bytes()).unwrap();
        let signer = ck.key.choose_scheme(&[scheme]).unwrap();
        assert_eq!(signer.scheme(), scheme);
        (ck.cert[0].clone(), signer.sign(msg).unwrap())
    }

    #[test]
    fn test_noop_verifier_accepts_anything() {
        let v = NoopServerCertVerifier::default();
        let cert = CertificateDer::from(vec![]);
        let name = ServerName::try_from("novg").unwrap();

        // Empty certificate, empty chain, empty OCSP
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], unix_time(NOW))
                .is_ok()
        );

        // Garbage that isn't even DER
        let garbage = CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(
            v.verify_server_cert(
                &garbage,
                std::slice::from_ref(&garbage),
                &name,
                &[0x00, 0x01],
                unix_time(NOW)
            )
            .is_ok()
        );

        // Valid certificate, but the name doesn't match its SAN (novg)
        let ck = pem_convert_to_rustls(TEST_KEY_1.as_bytes(), TEST_CERT_1.as_bytes()).unwrap();
        let cert = ck.cert[0].clone();
        let wrong_name = ServerName::try_from("wrong.example.com").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &wrong_name, &[], unix_time(NOW))
                .is_ok()
        );

        // Way past the certificate expiration (TEST_CERT_1 expires in 2033)
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], unix_time(9_000_000_000))
                .is_ok()
        );

        // And way before it was issued
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], unix_time(0))
                .is_ok()
        );
    }

    /// Makes sure the certificate that the noop verifier accepts is in fact
    /// rejected by a real verifier - i.e. that the test above isn't vacuous.
    #[test]
    fn test_noop_verifier_bypasses_real_verification() {
        let ck = pem_convert_to_rustls(TEST_KEY_1.as_bytes(), TEST_CERT_1.as_bytes()).unwrap();
        let cert = ck.cert[0].clone();
        let name = ServerName::try_from("novg").unwrap();

        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots
            .add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        assert!(added > 0 && ignored == 0);

        let real = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();

        // Self-signed snakeoil cert -> unknown issuer
        let err = real
            .verify_server_cert(&cert, &[], &name, &[], unix_time(NOW))
            .unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "unexpected error: {err:?}"
        );

        // Same input, but the noop verifier is happy with it
        assert!(
            NoopServerCertVerifier::default()
                .verify_server_cert(&cert, &[], &name, &[], unix_time(NOW))
                .is_ok()
        );
    }

    #[test]
    fn test_verify_tls12_signature() {
        let v = NoopServerCertVerifier::default();
        let msg = b"the quick brown fox jumps over the lazy dog";

        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
        ] {
            let (cert, sig) = sign(TEST_KEY_1, TEST_CERT_1, scheme, msg);

            // Correct signature
            assert!(
                v.verify_tls12_signature(msg, &cert, &dss(scheme, &sig))
                    .is_ok(),
                "{scheme:?} should verify"
            );

            // Signature over a different message
            assert!(
                v.verify_tls12_signature(b"other message", &cert, &dss(scheme, &sig))
                    .is_err()
            );

            // Tampered signature
            let mut bad = sig.clone();
            bad[0] ^= 0x01;
            assert!(
                v.verify_tls12_signature(msg, &cert, &dss(scheme, &bad))
                    .is_err()
            );

            // Truncated signature
            assert!(
                v.verify_tls12_signature(msg, &cert, &dss(scheme, &sig[..sig.len() - 1]))
                    .is_err()
            );

            // Empty signature
            assert!(
                v.verify_tls12_signature(msg, &cert, &dss(scheme, &[]))
                    .is_err()
            );

            // Valid signature, but verified against an unrelated certificate
            let other = pem_convert_to_rustls(TEST_KEY_2.as_bytes(), TEST_CERT_2.as_bytes())
                .unwrap()
                .cert[0]
                .clone();
            assert!(
                v.verify_tls12_signature(msg, &other, &dss(scheme, &sig))
                    .is_err()
            );

            // Valid signature, but the certificate can't be parsed
            let junk = CertificateDer::from(vec![0xde, 0xad]);
            assert!(
                v.verify_tls12_signature(msg, &junk, &dss(scheme, &sig))
                    .is_err()
            );
        }
    }

    #[test]
    fn test_verify_tls13_signature() {
        let v = NoopServerCertVerifier::default();
        let msg = b"the quick brown fox jumps over the lazy dog";

        let scheme = SignatureScheme::RSA_PSS_SHA256;
        let (cert, sig) = sign(TEST_KEY_1, TEST_CERT_1, scheme, msg);
        assert!(
            v.verify_tls13_signature(msg, &cert, &dss(scheme, &sig))
                .is_ok()
        );
        assert!(
            v.verify_tls13_signature(b"other message", &cert, &dss(scheme, &sig))
                .is_err()
        );

        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(
            v.verify_tls13_signature(msg, &cert, &dss(scheme, &bad))
                .is_err()
        );

        // RSA-PKCS#1 is forbidden in TLS1.3 (RFC8446 4.2.3), even though the
        // signature itself is valid and would pass in TLS1.2.
        let scheme = SignatureScheme::RSA_PKCS1_SHA256;
        let (cert, sig) = sign(TEST_KEY_1, TEST_CERT_1, scheme, msg);
        assert!(
            v.verify_tls12_signature(msg, &cert, &dss(scheme, &sig))
                .is_ok()
        );
        let err = v
            .verify_tls13_signature(msg, &cert, &dss(scheme, &sig))
            .unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
                )
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_verify_signature_unsupported_scheme() {
        let v = NoopServerCertVerifier::default();
        let msg = b"foobar";
        let (cert, sig) = sign(
            TEST_KEY_1,
            TEST_CERT_1,
            SignatureScheme::RSA_PSS_SHA256,
            msg,
        );

        // Neither an unknown scheme nor a scheme that this provider doesn't
        // support should be accepted.
        for scheme in [
            SignatureScheme::from(0xffff),
            SignatureScheme::ED448,
            SignatureScheme::RSA_PKCS1_SHA1,
        ] {
            assert!(
                !v.supported_verify_schemes().contains(&scheme),
                "{scheme:?} is unexpectedly supported"
            );
            assert!(
                v.verify_tls12_signature(msg, &cert, &dss(scheme, &sig))
                    .is_err()
            );
            assert!(
                v.verify_tls13_signature(msg, &cert, &dss(scheme, &sig))
                    .is_err()
            );
        }
    }

    #[test]
    fn test_supported_verify_schemes() {
        let v = NoopServerCertVerifier::default();
        let schemes = v.supported_verify_schemes();

        // These are the schemes that aws-lc-rs supports for verification
        for scheme in [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ] {
            assert!(schemes.contains(&scheme), "{scheme:?} is missing");
        }

        assert!(!schemes.contains(&SignatureScheme::RSA_PKCS1_SHA1));
        assert!(!schemes.contains(&SignatureScheme::ECDSA_SHA1_Legacy));
    }
}
