use super::common::{
    extract_chain_params, CommonAdditional, Either, FunctionParams, ListAccountAccount,
    ListAccountsAdditional, NewAccountAccount, SelectedAccount, ShakeAccountAccount, SignParams,
    SignTxAdditional, SignTxParams, SignTxTransaction, UpdateAccountAccount,
};
use super::Error;
use super::StorageController;
use crate::contract::Contract;
use crate::core::{Address, Transaction};
use crate::keystore::{CryptoType, Kdf, KdfDepthLevel, KeyFile, PBKDF2_KDF_NAME};
use crate::mnemonic::{gen_entropy, hd_path, HDPath, Language, Mnemonic, ENTROPY_BYTE_LENGTH};
use crate::rpc::common::{NewMnemonicAccount, SignTypedDataParams};
use crate::util;
use jsonrpc_core::{Params, Value};
use serde_json;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

static OPENRPC_SCHEMA: &[u8] = include_bytes!("../../openrpc.json");

pub fn openrpc_discover() -> Result<String, Error> {
    let contents = String::from_utf8_lossy(OPENRPC_SCHEMA).deref().to_string();

    Ok(contents)
}

pub fn list_accounts(
    params: Either<(), (ListAccountsAdditional,)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Vec<ListAccountAccount>, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (additional,) = params.into_right();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let res = storage
        .list_accounts(additional.show_hidden)?
        .iter()
        .map(|info| ListAccountAccount {
            name: info.name.clone(),
            address: info.address.clone(),
            description: info.description.clone(),
            hardware: info.is_hardware,
            is_hidden: info.is_hidden,
        })
        .collect();
    log::debug!(
        "Accounts listed with `show_hidden`: {}\n\t{:?}",
        additional.show_hidden,
        res
    );

    Ok(res)
}

pub fn hide_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&account.address)?;
    let res = storage.hide(&addr)?;
    log::debug!("Account hided: {}", addr);

    Ok(res)
}

pub fn unhide_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&account.address)?;
    let res = storage.unhide(&addr)?;
    log::debug!("Account unhided: {}", addr);

    Ok(res)
}

pub fn shake_account(
    params: Either<(ShakeAccountAccount,), (ShakeAccountAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    use crate::util::os_random;

    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = storage.search_by_address(&addr)?;
    match kf.crypto {
        CryptoType::Core(ref core) => {
            let pk = kf.decrypt_key(&account.old_passphrase)?;
            let new_kf = KeyFile::new_custom(
                pk,
                &account.new_passphrase,
                core.kdf_params.kdf,
                &mut os_random(),
                kf.name,
                kf.description,
            )?;
            storage.put(&new_kf)?;
            log::debug!("Account shaked: {}", kf.address);
        }
    };

    Ok(true)
}

pub fn update_account(
    params: Either<(UpdateAccountAccount,), (UpdateAccountAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<bool, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, mut kf) = storage.search_by_address(&addr)?;
    if !account.name.is_empty() {
        kf.name = Some(account.name);
    }
    if !account.description.is_empty() {
        kf.description = Some(account.description);
    }

    storage.put(&kf)?;
    log::debug!(
        "Account {} updated with name: {}, description: {}",
        kf.address,
        kf.name.unwrap_or_else(|| "".to_string()),
        kf.description.unwrap_or_else(|| "".to_string())
    );

    Ok(true)
}

pub fn import_account(
    params: Either<(Value,), (Value, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (raw, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let raw = serde_json::to_string(&raw)?;

    let kf = KeyFile::decode(&raw)?;
    storage.put(&kf)?;

    log::debug!("Account imported: {}", kf.address);

    Ok(format!("{}", kf.address))
}

pub fn export_account(
    params: Either<(SelectedAccount,), (SelectedAccount, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Value, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&account.address)?;

    let (_, kf) = storage.search_by_address(&addr)?;
    let value = serde_json::to_value(&kf)?;
    log::debug!("Account exported: {}", kf.address);

    Ok(value)
}

pub fn new_account(
    params: Either<(NewAccountAccount,), (NewAccountAccount, CommonAdditional)>,
    sec: KdfDepthLevel,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    if account.passphrase.is_empty() {
        return Err(Error::InvalidDataFormat("Empty passphrase".to_string()));
    }

    let kf = KeyFile::new(
        &account.passphrase,
        sec,
        Some(account.name),
        Some(account.description),
    )?;

    let addr = kf.address.to_string();
    storage.put(&kf)?;
    log::debug!("New account generated: {}", kf.address);

    Ok(addr)
}

pub fn sign_transaction(
    params: SignTxParams<
        (SignTxTransaction, String),
        (SignTxTransaction, String, SignTxAdditional),
    >,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Params, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (transaction, passphrase, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&transaction.from)?;
    let (_chain, chain_id) = extract_chain_params(&additional)?;

    match storage.search_by_address(&addr) {
        Ok((_, kf)) => match transaction.try_into() {
            Ok(tr) => {
                if passphrase.is_empty() {
                    return Err(Error::InvalidDataFormat("Missing passphrase".to_string()));
                }

                if let Ok(pk) = kf.decrypt_key(&passphrase) {
                    let raw = tr
                        .to_signed_raw(pk, chain_id)
                        .expect("Expect to sign a transaction");
                    let signed = Transaction::signed_rpl_into_raw_params(&raw);
                    log::debug!("Signed transaction to: {:?}\n\t raw: {:?}", &tr.to, signed);

                    Ok(signed)
                } else {
                    Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
                }
            }
            Err(err) => Err(Error::InvalidDataFormat(err.to_string())),
        },

        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}

pub fn sign(
    params: SignParams<(String, String, String, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Params, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (input, address, passphrase, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&address)?;
    let hash = util::keccak256(
        format!("\x19Ethereum Signed Message:\n{}{}", input.len(), input).as_bytes(),
    );
    match storage.search_by_address(&addr) {
        Ok((_, kf)) => {
            if passphrase.is_empty() {
                return Err(Error::InvalidDataFormat("Missing passphrase".to_string()));
            }
            if let Ok(pk) = kf.decrypt_key(&passphrase) {
                let signed = pk.sign_hash(hash)?;
                Ok(Params::Array(vec![Value::String(signed.into())]))
            } else {
                Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
            }
        }
        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}

pub fn sign_typed_data(
    params: SignTypedDataParams<(String, Value, String, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Params, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (address, typed_data, passphrase, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    let addr = Address::from_str(&address)?;

    let hash =
        util::typed::hash(typed_data).map_err(|err| Error::TypedDataError(err.to_string()))?;

    match storage.search_by_address(&addr) {
        Ok((_, kf)) => {
            if passphrase.is_empty() {
                return Err(Error::InvalidDataFormat("Missing passphrase".to_string()));
            }
            if let Ok(pk) = kf.decrypt_key(&passphrase) {
                let signed = pk.sign_hash(hash)?;
                Ok(Params::Array(vec![Value::String(signed.into())]))
            } else {
                Err(Error::InvalidDataFormat("Invalid passphrase".to_string()))
            }
        }
        Err(_) => Err(Error::InvalidDataFormat("Can't find account".to_string())),
    }
}

pub fn encode_function_call(
    params: Either<(Value,), (Value, FunctionParams)>,
) -> Result<String, Error> {
    let (_, inputs) = params.into_full();

    Contract::serialize_params(&inputs.types, inputs.values).map_err(From::from)
}

pub fn list_contracts(
    params: Either<(), (CommonAdditional,)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<Vec<serde_json::Value>, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (additional,) = params.into_right();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_contracts(&chain)?;

    Ok(storage.list())
}

pub fn import_contract(
    params: Either<(Value,), (Value, CommonAdditional)>,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<(), Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (raw, additional) = params.into_full();
    let (chain, _chain_id) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_contracts(&chain)?;

    storage.add(&raw)?;
    Ok(())
}

//pub fn export_contract(
//    params: Either<(Value,), (Value, FunctionParams)>,
//    storage: &Arc<Mutex<StorageController>>,
//) -> Result<Value, Error> {
//    let storage_ctrl = storage.lock().unwrap();
//    let (_, inputs) = params.into_full();
//    let storage = storage_ctrl.get_contracts(&additional.chain)?;
//}

pub fn generate_mnemonic() -> Result<String, Error> {
    let entropy = gen_entropy(ENTROPY_BYTE_LENGTH)?;
    let mnemonic = Mnemonic::new(Language::English, &entropy)?;

    Ok(mnemonic.sentence())
}

pub fn import_mnemonic(
    params: Either<(NewMnemonicAccount,), (NewMnemonicAccount, CommonAdditional)>,
    sec: &KdfDepthLevel,
    storage: &Arc<Mutex<StorageController>>,
) -> Result<String, Error> {
    let storage_ctrl = storage.lock().unwrap();
    let (account, additional) = params.into_full();
    let (chain, _) = extract_chain_params(&additional)?;
    let storage = storage_ctrl.get_keystore(&chain)?;
    if account.passphrase.is_empty() {
        return Err(Error::InvalidDataFormat("Empty passphrase".to_string()));
    }

    let mnemonic = Mnemonic::try_from(Language::English, &account.mnemonic)?;
    let hd_path = HDPath::try_from(&account.hd_path)?;
    let pk = hd_path::generate_key(&hd_path, &mnemonic.seed(""))?;

    let kdf = if cfg!(target_os = "windows") {
        Kdf::from_str(PBKDF2_KDF_NAME)?
    } else {
        Kdf::from(*sec)
    };

    let mut rng = util::os_random();
    let kf = KeyFile::new_custom(
        pk,
        &account.passphrase,
        kdf,
        &mut rng,
        Some(account.name),
        Some(account.description),
    )?;

    let addr = kf.address.to_string();
    storage.put(&kf)?;
    log::debug!("New mnemonic account generated: {}", kf.address);

    Ok(addr)
}
