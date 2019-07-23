//! # CLI wrapper for `jade-rs`
#![cfg(feature = "cli")]

mod cmd;
mod indicator;

use clap::App;
use env_logger::Builder;
use log::Record;
use std::env;
use std::io::Write;
use std::process::*;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// Get the current version.
pub fn version() -> &'static str {
    VERSION.unwrap_or("unknown")
}

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
        println!("v{}", version());
        exit(0);
    }

    match cmd::execute(&matches) {
        Ok(_) => exit(0),
        Err(e) => {
            log::error!("{}", e.to_string());
            exit(1)
        }
    };
}
