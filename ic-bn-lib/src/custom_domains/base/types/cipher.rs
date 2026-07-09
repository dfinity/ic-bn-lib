use super::super::traits::cipher::{CipherError, CiphersCertificates};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};

/// The length of the XChaCha20Poly1305 nonce in bytes.
const NONCE_LEN: usize = 24;

/// The length of the Poly1305 authentication tag in bytes.
const AUTH_TAG_LEN: usize = 16;

/// Minimum encrypted data length: nonce + auth tag + at least 1 byte of data.
const MIN_ENCRYPTED_DATA_LEN: usize = NONCE_LEN + AUTH_TAG_LEN + 1;

/// A cryptographic cipher for encrypting and decrypting certificate data.
pub struct CertificateCipher(XChaCha20Poly1305);

// Custom Debug implementation to avoiding exposing any sensitive data.
impl std::fmt::Debug for CertificateCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificateCipher")
    }
}

impl CertificateCipher {
    /// Creates a new CertificateCipher.
    pub fn new(key: &Key) -> Self {
        Self(XChaCha20Poly1305::new(key))
    }
}

impl CiphersCertificates for CertificateCipher {
    /// Encrypts the provided data using XChaCha20Poly1305.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        if data.is_empty() {
            return Err(CipherError::InvalidInput(
                "Cannot encrypt empty data".to_string(),
            ));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let encrypted_data = self
            .0
            .encrypt(nonce, data)
            .map_err(|e| CipherError::EncryptionFailed(format!("Encryption failed: {e}")))?;

        let mut result = Vec::with_capacity(NONCE_LEN + encrypted_data.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted_data);

        Ok(result)
    }

    /// Decrypts the provided encrypted data.
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Validate input length
        if encrypted_data.len() < MIN_ENCRYPTED_DATA_LEN {
            return Err(CipherError::InvalidInput(format!(
                "Encrypted data too short: got {} bytes, minimum {MIN_ENCRYPTED_DATA_LEN} required",
                encrypted_data.len(),
            )));
        }

        // Check above ensures this split won't panic
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);

        let decrypted_data = self
            .0
            .decrypt(nonce, ciphertext)
            .map_err(|e| CipherError::DecryptionFailed(format!("Decryption failed: {e}")))?;

        Ok(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;

    impl CertificateCipher {
        /// Creates a new CertificateCipher with a randomly generated key.
        pub fn new_with_random_key() -> Self {
            let key = XChaCha20Poly1305::generate_key(&mut OsRng);
            Self::new(&key)
        }
    }

    fn create_test_cipher() -> CertificateCipher {
        CertificateCipher::new_with_random_key()
    }

    /// Sample certificate in PEM format
    const SAMPLE_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTMwODI3MjM1NDA3WhcNMTMwOTI2MjM1NDA3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuW9H/4Aiw+7eEXYEaK2CExjzxpKTQ4FNlz1k6VNZ8PKR6E6VlFGRWBP7
k1sN8Uj0y6JvCX/XMzHn4zOqCN5z1c2K2QXgCQ7lR8BNl5sKZ1y7YYKdV9y/4I+z
7m8vK2Q5R9R2cOQ5vB5vOK2s5dQ8v6rK1oP2l3FaQ3M1Q5s3T8L6K7Q5YQ8o9J5g
XQ7lF9k4p1Y5vM7Q2c5I8P6l2C7sG1m9t5K1B2q2F5c8u1F4s9K6c2l7T6F6q7m
5vO4d7i9j2A1K8L4o9M5Q7vR2qF8f3c9m4u7a6Y2vN1w3P5t9G2k8C6r7o4B1q
3Z8b9a5L2F6k7Y4v8c5m1N2q9M8T4wIDAQABo1AwTjAdBgNVHQ4EFgQUjqP6Y3
B6k7Q5vR2qF8f3c9m4u7aMwHwYDVR0jBBgwFoAUjqP6Y3B6k7Q5vR2qF8f3c9m4
u7aMwDANBgkqhkiG9w0BAQUFAAOCAQEAi7HfnOJ5U6Q2q8z7T6o5K1X8C7M4F9w
6d5T8F6h3C9A2g1L5O7m6B4K8q1v9Q5t7G6f2d8A3j9M2o6n1R4u7s5H8K2l7m
Q9d6F7p8G4i2k5A8v7J6T4m9c1Y5p3O8q7D2F6H9n4m7b5Q6t8L2p9K6S7g4U
-----END CERTIFICATE-----"#;

    /// Sample private key in PEM format
    const SAMPLE_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5b0f/gCLD7t4R
dgRorYITGPPGkpNDgU2XPWTpU1nw8pHoTpWUUZFYE/uTWw3xSPTLom8Jf9czMefjM6oI3nPVzYrZBeAJDuVHwE2XmwpnXLthgp1X3L/gj7PubY8rZDlH1HZw5Dm8Hm84razl1Dy/qsrWg/aXcVpDczVDmzdPwvortDlhDyj0nmBdDuUX2TinVjm8ztDZzkjw/qXYLuwbWb23krUHarYXlzy7UXiz0rpzaXtPoXqrubm87h3uL2PYDUL4wvijEzlDu9HaoXx/dz2bi7trpja83XDc/m30baT2XqrtjgHWrdn2vw1rks4X6TtjgI/xzmbU3ar0zxPjAgMBAAECggEAOCqbLhF2C2Q5o6b5z9L1q3K8vF5a7m9Q8P9h6K2o5n3v8F6u7t4K8q1v9Q5t7G6f2d8A3j9M2o6n1R4u7s5H8K2l7mQ9d6F7p8G4i2k5A8v7J6T4m9c1Y5p3O8q7D2F6H9n4m7b5Q6t8L2p9K6S7g4U1q5K7O2f8d5A9c7h6t4B2m9K5o8v3l7Q4p6F1u9Y2s7d4c8m6n7o5p2f9A3c8v6b1Q4t7G2o9K5m8d6F7u4Y1s9P6t2K8o3v5c7m1Q4
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = create_test_cipher();
        let original_data = b"This is a test message.";

        let encrypted = cipher
            .encrypt(original_data)
            .expect("Encryption should succeed");
        let decrypted = cipher
            .decrypt(&encrypted)
            .expect("Decryption should succeed");

        assert_eq!(original_data, decrypted.as_slice());
    }

    #[test]
    fn test_real_certificate_data_encoding() {
        // Arrange
        let cipher = create_test_cipher();

        let cert_data = SAMPLE_CERTIFICATE_PEM.as_bytes();

        // Act
        let encrypted = cipher
            .encrypt(cert_data)
            .expect("Certificate encryption should succeed");
        let decrypted = cipher
            .decrypt(&encrypted)
            .expect("Certificate decryption should succeed");

        assert_eq!(cert_data, decrypted.as_slice());

        // Assert
        let decrypted_str =
            String::from_utf8(decrypted).expect("Decrypted certificate should be valid UTF-8");
        assert!(decrypted_str.contains("-----BEGIN CERTIFICATE-----"));
        assert!(decrypted_str.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_real_private_key_data_encoding() {
        // Arrange
        let cipher = create_test_cipher();

        let key_data = SAMPLE_PRIVATE_KEY_PEM.as_bytes();

        // Act
        let encrypted = cipher
            .encrypt(key_data)
            .expect("Private key encryption should succeed");

        let decrypted = cipher
            .decrypt(&encrypted)
            .expect("Private key decryption should succeed");

        // Assert
        assert_eq!(key_data, decrypted.as_slice());
        let decrypted_str =
            String::from_utf8(decrypted).expect("Decrypted private key should be valid UTF-8");
        assert!(decrypted_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(decrypted_str.contains("-----END PRIVATE KEY-----"));
    }
}
