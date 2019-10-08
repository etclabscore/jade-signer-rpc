//! # Execute command

mod error;
#[macro_use]
mod arg_handlers;

pub use self::arg_handlers::*;
pub use self::error::Error;

use clap::ArgMatches;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::keystore::KdfDepthLevel;
use crate::storage::{default_path, StorageController, StorageType};

type ExecResult = Result<(), Error>;

const DEFAULT_CHAIN_NAME: &str = "mainnet";

/// Create new command executor
pub fn execute(matches: &ArgMatches) -> ExecResult {
    let env = EnvVars::parse();

    let chain = matches.value_of("chain").unwrap_or(DEFAULT_CHAIN_NAME);
    log::info!("Chain name: {}", DEFAULT_CHAIN_NAME);

    let mut base_path = PathBuf::new();
    if let Some(p) = matches
        .value_of("base-path")
        .or_else(|| env.emerald_base_path.as_ref().map(String::as_str))
    {
        base_path.push(&p)
    } else {
        base_path = default_path();
    }

    let storage_type = if let Some(storage_type) = matches.value_of("storage-type") {
        StorageType::from_str(storage_type)?
    } else {
        StorageType::RocksDB
    };

    let storage_ctrl = StorageController::new(base_path, storage_type)?;

    log::info!("Starting Jade Signer - v{}", crate::version());
    let host = matches.value_of("host").unwrap_or_default();
    let port = matches.value_of("port").unwrap_or_default();
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>()?;
    let sec_lvl = get_security_lvl(matches)?;

    log::info!("Chain set to '{}'", chain);
    log::info!("Security level set to '{}'", sec_lvl);

    crate::rpc::start(&addr, storage_ctrl, Some(sec_lvl));

    Ok(())
}
