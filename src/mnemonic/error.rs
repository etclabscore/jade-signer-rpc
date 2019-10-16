//! # Mnemonic sentence generation errors

use failure::Fail;
use std::{error, fmt, io};

/// `Mnemonic` generation errors
#[derive(Debug, Fail)]
pub enum Error {
    /// Mnemonic sentence generation error
    #[fail(display = "Mnemonic generation error: {}", _0)]
    MnemonicError(String),

    /// BIP32 key generation error
    #[fail(display = "BIP32 generation error: {}", _0)]
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
