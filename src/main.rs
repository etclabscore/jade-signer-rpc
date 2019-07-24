//! # Ethereum Classic web3 like connector library
#![deny(missing_docs)]

mod contract;
mod core;
mod keystore;
mod mnemonic;
mod rpc;
mod storage;
mod util;
mod signer;

use self::core::*;
use self::rpc::start;
use self::util::*;

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use hex::{FromHex, ToHex};
    pub use regex::Regex;
}

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Get the current Jade Signer version.
pub fn version() -> &'static str {
    VERSION.unwrap_or("unknown")
}

use clap::App;
use env_logger::Builder;
use log::Record;
use std::env;
use std::io::Write;
use std::process::*;

fn main() {
    let yaml = clap::load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    match matches.occurrences_of("verbose") {
        0 => env::set_var("RUST_LOG", "error"),
        1 => env::set_var("RUST_LOG", "info"),
        2 | _ => env::set_var("RUST_LOG", "debug"),
    }

    let mut log_builder = Builder::new();
    if env::var("RUST_LOG").is_ok() {
        log_builder.parse_filters(&env::var("RUST_LOG").unwrap());
    }
    log_builder.format(|buf, record: &Record| {
        writeln!(
            buf,
            "{}",
            format!("[{}]\t{}", record.level(), record.args())
        )
    });
    log_builder.init();

    if matches.is_present("version") {
        println!("v{}", crate::version());
        exit(0);
    }

    match signer::cmd::execute(&matches) {
        Ok(_) => exit(0),
        Err(e) => {
            log::error!("{}", e.to_string());
            exit(1)
        }
    };
}
