//! # Core domain logic module errors

use ethabi;
use failure::Fail;
use hex;
use secp256k1;

/// Core domain logic errors
#[derive(Debug, Fail)]
pub enum Error {
    /// Invalid ABI
    #[fail(display = "Invalid ABI {}", _0)]
    InvalidABI(String),

    /// An invalid length
    #[fail(display = "Invalid length: {}", _0)]
    InvalidLength(usize),

    /// An unexpected hexadecimal prefix (should be '0x')
    #[fail(display = "Invalid hex data length: {}", _0)]
    InvalidHexLength(String),

    /// An unexpected hexadecimal encoding
    #[fail(display = "Unexpected hexadecimal encoding: {:?}", _0)]
    UnexpectedHexEncoding(hex::FromHexError),

    /// ECDSA crypto error
    #[fail(display = "ECDSA crypto error: {}", _0)]
    EcdsaCrypto(secp256k1::Error),
}

impl From<ethabi::Error> for Error {
    fn from(err: ethabi::Error) -> Self {
        Error::InvalidABI(format!("Invalid ABI {:?}", err))
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::UnexpectedHexEncoding(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::EcdsaCrypto(err)
    }
}
