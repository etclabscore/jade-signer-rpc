//! # Helpers for command execution

use super::Error;
use super::{ArgMatches, KdfDepthLevel};
use std::env;
use std::str::FromStr;

/// Environment variables used to change default variables
#[derive(Default, Debug)]
pub struct EnvVars {
    pub emerald_base_path: Option<String>,
    pub emerald_host: Option<String>,
    pub emerald_port: Option<String>,
    pub emerald_chain: Option<String>,
    pub emerald_chain_id: Option<String>,
    pub emerald_gas: Option<String>,
    pub emerald_gas_price: Option<String>,
    pub emerald_security_level: Option<String>,
    pub emerald_node: Option<String>,
}

impl EnvVars {
    /// Collect environment variables to overwrite default values
    pub fn parse() -> EnvVars {
        let mut vars = EnvVars::default();
        for (key, value) in env::vars() {
            match key.as_ref() {
                "EMERALD_BASE_PATH" => vars.emerald_base_path = Some(value),
                "EMERALD_HOST" => vars.emerald_host = Some(value),
                "EMERALD_PORT" => vars.emerald_port = Some(value),
                "EMERALD_CHAIN" => vars.emerald_chain = Some(value),
                "EMERALD_CHAIN_ID" => vars.emerald_chain_id = Some(value),
                "EMERALD_GAS" => vars.emerald_gas = Some(value),
                "EMERALD_GAS_PRICE" => vars.emerald_gas_price = Some(value),
                "EMERALD_SECURITY_LEVEL" => vars.emerald_security_level = Some(value),
                "EMERALD_NODE" => vars.emerald_node = Some(value),
                _ => (),
            }
        }
        vars
    }
}

/// Parse address from command-line argument
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
///
pub fn get_security_lvl(matches: &ArgMatches) -> Result<KdfDepthLevel, Error> {
    let kdf = match matches.value_of("security-level") {
        Some(sec) => KdfDepthLevel::from_str(sec)?,
        None => KdfDepthLevel::default(),
    };

    Ok(kdf)
}
