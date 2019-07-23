//! # Ethereum Classic web3 like connector library
#![deny(missing_docs)]

mod contract;
mod core;
pub mod keystore;
pub mod mnemonic;
pub mod rpc;
pub mod storage;
mod util;

pub use self::core::*;
pub use self::rpc::start;
pub use self::util::*;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Get the current Emerald version.
pub fn version() -> &'static str {
    VERSION.unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use hex::{FromHex, ToHex};
    pub use regex::Regex;
}
