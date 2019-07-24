use super::contracts::ContractStorage;
use super::keyfile::KeystoreError;
use super::{
    build_contract_storage, build_keyfile_storage, build_path,
    KeyfileStorage,
};
use std::collections::HashMap;
use std::path::Path;
use crate::storage::StorageType;

const CHAIN_NAMES: &[&str; 9] = &[
    "eth",
    "morden",
    "ropsten",
    "rinkeby",
    "rootstock-main",
    "rootstock-test",
    "kovan",
    "etc",
    "etc-morden",
];

/// Controller to switch storage according to specified chain
pub struct StorageController {
    keyfile_storages: HashMap<String, Box<dyn KeyfileStorage>>,
    contract_storages: HashMap<String, Box<ContractStorage>>,
}

impl StorageController {
    /// Create new `StorageController`
    /// with a subfolders for
    pub fn new<P: AsRef<Path>>(base_path: P, storage_type: StorageType) -> Result<StorageController, KeystoreError> {
        let mut st = StorageController::default();

        for id in CHAIN_NAMES {
            st.keyfile_storages.insert(
                id.to_string(),
                build_keyfile_storage(build_path(base_path.as_ref(), id, "keystore"), storage_type)?,
            );
            st.contract_storages.insert(
                id.to_string(),
                build_contract_storage(build_path(base_path.as_ref(), id, "contracts"))?,
            );
        }

        Ok(st)
    }

    /// Get `KeyFile` storage for specified chain
    pub fn get_keystore(&self, chain: &str) -> Result<&dyn KeyfileStorage, KeystoreError> {
        match self.keyfile_storages.get(chain) {
            Some(st) => Ok(&**st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }

    /// Get `Contract` storage for specified chain
    pub fn get_contracts(&self, chain: &str) -> Result<&ContractStorage, KeystoreError> {
        match self.contract_storages.get(chain) {
            Some(st) => Ok(&st),
            None => Err(KeystoreError::StorageError(format!(
                "No storage for: {}",
                chain
            ))),
        }
    }
}

impl Default for StorageController {
    fn default() -> Self {
        StorageController {
            keyfile_storages: HashMap::new(),
            contract_storages: HashMap::new(),
        }
    }
}
