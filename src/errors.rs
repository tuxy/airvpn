//! Error types for the AirVPN library.
//!
//! All fallible operations return [`Result<T, Error>`]. The [`Error`] enum
//! covers HTTP failures, XML/JSON parsing, encryption/decryption issues,
//! WireGuard config problems, and API-level errors returned by AirVPN.

use base64::DecodeError;

/// All errors that can be produced by this library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An HTTP request failed (network error, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// The server returned a non-200 HTTP status code.
    #[error("HTTP status {0}")]
    HttpStatus(u16),

    /// XML parsing failed.
    #[error("XML parse error: {0}")]
    Xml(#[from] roxmltree::Error),

    /// JSON deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The AirVPN server returned an error message in its XML response.
    #[error("server returned error: {0}")]
    Server(String),

    /// Every bootstrap URL was tried and all failed.
    #[error("all bootstrap servers failed: {0}")]
    AllServersFailed(String),

    /// RSA or AES encryption failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// AES decryption or PKCS7 unpadding failed.
    #[error("decryption error: {0}")]
    Decryption(String),

    /// An RSA key could not be constructed from the given modulus/exponent.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A WireGuard configuration could not be extracted from the user XML.
    #[error("wireguard config error: {0}")]
    Wireguard(String),

    /// The public status API returned a JSON error payload.
    #[error("API error: {0}")]
    Api(String),

    /// [`AirVPNBuilder::build`] was called without setting credentials.
    ///
    /// [`AirVPNBuilder::build`]: crate::AirVPNBuilder::build
    #[error("missing credentials")]
    MissingCredentials,

    /// A byte slice that was expected to be valid UTF-8 was not.
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] DecodeError),
}

/// A specialised `Result` type alias for this library.
pub type Result<T> = std::result::Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.to_string())
    }
}