//! # Storage for `KeyFiles` and `Contracts`

mod contracts;
mod keyfile;
mod storage_ctrl;

pub use self::contracts::ContractStorage;
pub use self::keyfile::*;
pub use self::storage_ctrl::StorageController;
pub use self::KeystoreError;
use std::boxed::Box;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Base dir for internal data, all chain-related should be store in subdirectories
#[derive(Debug, Clone)]
pub struct Storages {
    /// base dir
    base_dir: PathBuf,
}

/// Available storage types
#[derive(Debug, Clone, Copy)]
pub enum StorageType {
    /// Store keyfiles on filesystem (as files)
    Filesystem,
    /// Store keyfiles in RocksDB
    RocksDB,
}

impl FromStr for StorageType {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "filesystem" => Ok(StorageType::Filesystem),
            "rocksdb" => Ok(StorageType::RocksDB),
            other => Err(failure::format_err!("Unknown storage type {:?}, available types: ['rocksdb', 'filesystem']", other)),
        }
    }
}

/// Default path (*nix)
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
pub fn default_path() -> PathBuf {
    let mut config_dir = dirs::home_dir().expect("Expect path to home dir");
    config_dir.push(".jade_signer");
    config_dir
}

/// Default path (Mac OS X)
#[cfg(target_os = "macos")]
pub fn default_path() -> PathBuf {
    let mut config_dir = dirs::home_dir().expect("Expect path to home dir");
    config_dir.push("Library");
    config_dir.push("JadeSigner");
    config_dir
}

/// Default path (Windows OS)
#[cfg(target_os = "windows")]
pub fn default_path() -> PathBuf {
    let app_data_var = dirs::data_dir().expect("Failed to get platform data dir");
    let mut config_dir = PathBuf::from(app_data_var);
    config_dir.push(".jade_signer");
    config_dir
}

/// Build `chain` specific path for selected `folder`
///
/// # Arguments:
///
/// * `base_path` - base folder for storage
/// * `chain` - chain name
/// * `folder` - destination folder
///
pub fn build_path(base_path: &Path, chain: &str, folder: &str) -> PathBuf {
    let mut path = PathBuf::from(base_path);
    path.push(chain);
    path.push(folder);
    path
}

/// Creates specific type of `KeyFile` storage (database or filesystem)
///
/// # Arguments:
///
/// * `keystore_path` - path for `KeyFile` storage
///
pub fn build_keyfile_storage<P>(path: P, storage_type: StorageType) -> Result<Box<dyn KeyfileStorage>, KeystoreError>
where
    P: AsRef<Path>,
{
    match storage_type {
        StorageType::RocksDB => {
            let mut p = PathBuf::new();
            p.push(path);
            p.push(".db");
            match DbStorage::new(p) {
                Ok(db) => Ok(Box::new(db)),
                Err(_) => Err(KeystoreError::StorageError(
                    "Can't create database Keyfile storage".to_string(),
                )),
            }
        },
        StorageType::Filesystem => Ok(Box::new(FsStorage::new(path))),
    }
}

/// Creates specific type of `Contract` storage (database or filesystem)
///
/// # Arguments:
///
/// * `path` - path for `Contract` storage
///
pub fn build_contract_storage<P>(path: P) -> Result<Box<ContractStorage>, KeystoreError>
where
    P: AsRef<Path>,
{
    // TODO: implement DB storage. Add conditional compilation.
    let mut p = PathBuf::new();
    p.push(path);
    fs::create_dir_all(&p)?;

    Ok(Box::new(ContractStorage::new(p)))
}