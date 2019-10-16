//! # Keystore files (UTC / JSON) module errors

use super::core;
use failure::Fail;

/// Keystore file errors
#[derive(Debug, Fail)]
pub enum Error {
    /// An unsupported cipher
    #[fail(display = "Unsupported cipher: {}", _0)]
    UnsupportedCipher(String),

    /// An unsupported key derivation function
    #[fail(display = "Unsupported key derivation function: {}", _0)]
    UnsupportedKdf(String),

    /// An unsupported pseudo-random function
    #[fail(display = "Unsupported pseudo-random function: {}", _0)]
    UnsupportedPrf(String),

    /// `keccak256_mac` field validation failed
    #[fail(display = "Message authentication code failed")]
    FailedMacValidation,

    /// Core module error wrapper
    #[fail(display = "{:?}", _0)]
    CoreFault(core::Error),

    /// Invalid Kdf depth value
    #[fail(display = "Invalid security level: {}", _0)]
    InvalidKdfDepth(String),
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::CoreFault(err)
    }
}
