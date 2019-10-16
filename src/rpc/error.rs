//! # JSON RPC module errors

use super::core;
use super::storage;
use crate::contract;
use crate::keystore;
use crate::mnemonic;
use failure::Fail;
use hex;
use jsonrpc_core;
use reqwest;
use serde_json;
use std::io;

/// JSON RPC errors
#[derive(Debug, Fail)]
pub enum Error {
    /// Http client error
    #[fail(display = "HTTP client error: {:?}", _0)]
    HttpClient(reqwest::Error),
    /// RPC error
    #[fail(display = "RPC error: {:?}", _0)]
    RPC(jsonrpc_core::Error),
    /// Invalid data format
    #[fail(display = "Invalid data format: {}", _0)]
    InvalidDataFormat(String),
    /// Storage error
    #[fail(display = "Keyfile storage error: {}", _0)]
    StorageError(String),
    /// Storage error
    #[fail(display = "Contract ABI error: {}", _0)]
    ContractAbiError(String),
    /// Mnemonic phrase operations error
    #[fail(display = "Mnemonic error: {}", _0)]
    MnemonicError(String),
    /// Typed Data Error
    TypedDataError(String),
}

impl From<keystore::Error> for Error {
    fn from(err: keystore::Error) -> Self {
        Error::InvalidDataFormat(format!("keystore: {}", err.to_string()))
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::InvalidDataFormat(e.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::HttpClient(err)
    }
}

impl From<core::Error> for Error {
    fn from(err: core::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::InvalidDataFormat(err.to_string())
    }
}

impl From<jsonrpc_core::Error> for Error {
    fn from(err: jsonrpc_core::Error) -> Self {
        Error::RPC(err)
    }
}

impl From<storage::KeystoreError> for Error {
    fn from(err: storage::KeystoreError) -> Self {
        Error::StorageError(err.to_string())
    }
}

impl From<contract::Error> for Error {
    fn from(err: contract::Error) -> Self {
        Error::ContractAbiError(err.to_string())
    }
}

impl From<mnemonic::Error> for Error {
    fn from(err: mnemonic::Error) -> Self {
        Error::MnemonicError(err.to_string())
    }
}

impl Into<jsonrpc_core::Error> for Error {
    fn into(self) -> jsonrpc_core::Error {
        jsonrpc_core::Error::internal_error()
    }
}
