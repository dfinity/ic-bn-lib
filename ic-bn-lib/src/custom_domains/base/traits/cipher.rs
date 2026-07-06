use thiserror::Error;

/// Errors that can occur during encryption/decryption operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherError {
    /// Encryption operation failed
    #[error("Failed to encrypt data: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("Failed to decrypt data: {0}")]
    DecryptionFailed(String),

    /// Invalid input data format
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
}

/// Trait for encrypting and decrypting certificate data.
pub trait CiphersCertificates: Send + Sync + std::fmt::Debug {
    /// Encrypts the provided data.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError>;

    /// Decrypts the provided encrypted data.
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError>;
}
