//! # Mnemonic sentence generation errors

use std::{error, fmt, io};

/// `Mnemonic` generation errors
#[derive(Debug)]
pub enum Error {
    /// Mnemonic sentence generation error
    MnemonicError(String),

    /// BIP32 key generation error
    KeyGenerationError(String),
}

impl From<crate::core::Error> for Error {
    fn from(err: crate::core::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl<'a> From<&'a str> for Error {
    fn from(err: &str) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::MnemonicError(err)
    }
}

impl From<bitcoin::Error> for Error {
    fn from(e: bitcoin::Error) -> Self {
        Error::KeyGenerationError(e.to_string())
    }
}

impl From<bitcoin::util::bip32::Error> for Error {
    fn from(e: bitcoin::util::bip32::Error) -> Self {
        Error::KeyGenerationError(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MnemonicError(ref str) => write!(f, "Mnemonic generation error: {}", str),
            Error::KeyGenerationError(ref str) => write!(f, "BIP32 generation error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Mnemonic generation error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            _ => None,
        }
    }
}
