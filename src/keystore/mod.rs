//! # Keystore files (UTC / JSON) encrypted with a passphrase module
//!
//! [Web3 Secret Storage Definition](
//! https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition)
mod cipher;
mod error;
mod kdf;
mod prf;
#[macro_use]
mod serialize;

pub use self::cipher::Cipher;
pub use self::error::Error;
pub use self::kdf::{Kdf, KdfDepthLevel, KdfParams, PBKDF2_KDF_NAME};
pub use self::prf::Prf;
pub use self::serialize::Error as SerializeError;
pub use self::serialize::{try_extract_address, CoreCrypto, Iv, Mac, SerializableKeyFileCore};
use super::core::{self, Address, PrivateKey};
use super::util::{self, keccak256, to_arr, KECCAK256_BYTES};

use std::convert::From;
use std::str::FromStr;
use std::{cmp, fmt};

use rand::{OsRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

byte_array_struct!(Salt, KDF_SALT_BYTES);

/// A keystore file (account private core encrypted with a passphrase)
#[derive(Deserialize, Debug, Clone, Eq)]
pub struct KeyFile {
    /// Specifies if `Keyfile` is visible
    pub visible: Option<bool>,

    /// User specified name
    pub name: Option<String>,

    /// User specified description
    pub description: Option<String>,

    /// Address
    pub address: Address,

    /// UUID v4
    pub uuid: Uuid,

    ///
    pub crypto: CryptoType,
}

/// Variants of `crypto` section in `Keyfile`
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum CryptoType {
    /// normal Web3 Secret Storage
    Core(CoreCrypto),
}

impl KeyFile {
    /// Creates a new `KeyFile` with specified passphrase at random (`rand::OsRng`)
    ///
    /// # Arguments
    ///
    /// * `passphrase` - password for key derivation function
    ///
    pub fn new(
        passphrase: &str,
        sec_level: KdfDepthLevel,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<KeyFile, Error> {
        let mut rng = os_random();

        let kdf = if cfg!(target_os = "windows") {
            Kdf::from_str(PBKDF2_KDF_NAME)?
        } else {
            Kdf::from(sec_level)
        };

        Self::new_custom(
            PrivateKey::gen_custom(&mut rng),
            passphrase,
            kdf,
            &mut rng,
            name,
            description,
        )
    }

    /// Creates a new `KeyFile` with specified `PrivateKey`, passphrase, key derivation function
    /// and with given custom random generator
    ///
    /// # Arguments
    ///
    /// * `pk` - a private key
    /// * `passphrase` - password for key derivation function
    /// * `kdf` - customized key derivation function
    /// * `rnd` - predefined random number generator
    ///
    pub fn new_custom<R: Rng>(
        pk: PrivateKey,
        passphrase: &str,
        kdf: Kdf,
        rng: &mut R,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<KeyFile, Error> {
        let mut kf = KeyFile {
            uuid: rng.gen::<Uuid>(),
            name,
            description,
            ..Default::default()
        };

        match &mut kf.crypto {
            CryptoType::Core(core) => core.kdf_params.kdf = kdf,
        }

        kf.encrypt_key_custom(pk, passphrase, rng);
        kf.address = kf.decrypt_address(passphrase)?;

        Ok(kf)
    }

    /// Decrypt public address from keystore file by a password
    pub fn decrypt_address(&self, password: &str) -> Result<Address, Error> {
        let pk = self.decrypt_key(password)?;
        pk.to_address().map_err(Error::from)
    }

    /// Decrypt private key from keystore file by a password
    pub fn decrypt_key(&self, passphrase: &str) -> Result<PrivateKey, Error> {
        match self.crypto {
            CryptoType::Core(ref core) => {
                let derived = core.kdf_params.kdf.derive(
                    core.kdf_params.dklen,
                    &core.kdf_params.salt,
                    passphrase,
                );

                let mut v = derived[16..32].to_vec();
                v.extend_from_slice(&core.cipher_text);

                let mac: [u8; KECCAK256_BYTES] = core.mac.into();
                if keccak256(&v) != mac {
                    return Err(Error::FailedMacValidation);
                }

                Ok(PrivateKey(to_arr(&core.cipher.encrypt(
                    &core.cipher_text,
                    &derived[0..16],
                    &core.cipher_params.iv,
                ))))
            }
        }
    }

    /// Encrypt a new private key for keystore file with a passphrase
    pub fn encrypt_key(&mut self, pk: PrivateKey, passphrase: &str) {
        self.encrypt_key_custom(pk, passphrase, &mut os_random());
    }

    /// Encrypt a new private key for keystore file with a passphrase
    /// and with given custom random generator
    pub fn encrypt_key_custom<R: Rng>(&mut self, pk: PrivateKey, passphrase: &str, rng: &mut R) {
        match self.crypto {
            CryptoType::Core(ref mut core) => {
                let mut buf_salt: [u8; KDF_SALT_BYTES] = [0; KDF_SALT_BYTES];
                rng.fill_bytes(&mut buf_salt);
                core.kdf_params.salt = Salt::from(buf_salt);

                let derived = core.kdf_params.kdf.derive(
                    core.kdf_params.dklen,
                    &core.kdf_params.salt,
                    passphrase,
                );

                let mut buf_iv: [u8; CIPHER_IV_BYTES] = [0; CIPHER_IV_BYTES];
                rng.fill_bytes(&mut buf_iv);
                core.cipher_params.iv = Iv::from(buf_iv);

                core.cipher_text =
                    core.cipher
                        .encrypt(&pk, &derived[0..16], &core.cipher_params.iv);

                let mut v = derived[16..32].to_vec();
                v.extend_from_slice(&core.cipher_text);
                core.mac = Mac::from(keccak256(&v));
            }
        }
    }
}

impl Default for KeyFile {
    fn default() -> Self {
        KeyFile {
            visible: Some(true),
            name: None,
            description: None,
            address: Address::default(),
            uuid: Uuid::default(),
            crypto: CryptoType::Core(CoreCrypto::default()),
        }
    }
}

impl From<Uuid> for KeyFile {
    fn from(uuid: Uuid) -> Self {
        KeyFile {
            uuid,
            ..Default::default()
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl PartialOrd for KeyFile {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyFile {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.uuid)
    }
}

/// Create random number generator
pub fn os_random() -> OsRng {
    OsRng::new().expect("Expect OS specific random number generator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use hex::FromHex;
    use crate::storage::{DbStorage, FsStorage, KeyfileStorage};
    use crate::{Address, KECCAK256_BYTES};
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tempdir::TempDir;
    use uuid::Uuid;

    #[test]
    fn should_create_keyfile() {
        let pk = PrivateKey::gen();
        let kdf = Kdf::from((8, 2, 1));
        let kf = KeyFile::new_custom(pk, "1234567890", kdf, &mut rand::thread_rng(), None, None)
            .unwrap();

        if let CryptoType::Core(ref core) = kf.crypto {
            assert_eq!(core.kdf_params.kdf, kdf);
        } else {
            assert!(false);
        }

        assert_eq!(kf.decrypt_key("1234567890").unwrap(), pk);
    }

    const PRJ_DIR: Option<&'static str> = option_env!("CARGO_MANIFEST_DIR");

    macro_rules! arr {
        ($bytes:expr, $num:expr) => {{
            let mut arr = [0u8; $num];
            arr.copy_from_slice($bytes);
            arr
        }};
    }

    pub fn temp_dir() -> PathBuf {
        let dir = TempDir::new("jade").unwrap();
        File::create(dir.path()).ok();
        dir.into_path()
    }

    pub fn file_content<P: AsRef<Path>>(path: P) -> String {
        let mut text = String::new();

        File::open(path)
            .expect("Expect read file content")
            .read_to_string(&mut text)
            .ok();

        text
    }

    pub fn keyfile_path(name: &str) -> PathBuf {
        let mut path = keystore_path();
        path.push(name);
        path
    }

    pub fn keystore_path() -> PathBuf {
        let mut buf = PathBuf::from(PRJ_DIR.expect("Expect project directory"));
        buf.push("test_data/keystore/serialize");
        buf
    }

    #[test]
    fn should_decrypt_private_key_protected_by_scrypt() {
        let path =
            keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

        let keyfile = KeyFile::decode(&file_content(path)).unwrap();

        assert!(keyfile.decrypt_key("_").is_err());
        assert_eq!(
            keyfile.decrypt_key("1234567890").unwrap().to_string(),
            "0xfa384e6fe915747cd13faa1022044b0def5e6bec4238bec53166487a5cca569f"
        );
    }

    #[test]
    fn should_decrypt_private_key_protected_by_pbkdf2() {
        let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

        let keyfile = KeyFile::decode(&file_content(path)).unwrap();

        assert!(keyfile.decrypt_key("_").is_err());
        assert_eq!(
            keyfile.decrypt_key("1234567890").unwrap().to_string(),
            "0x00b413b37c71bfb92719d16e28d7329dea5befa0d0b8190742f89e55617991cf"
        );
    }

    #[test]
    fn should_decode_keyfile_without_address() {
        let path = keyfile_path("UTC--2017-03-20T17-03-12Z--37e0d14f-7269-7ca0-4419-d7b13abfeea9");

        let mut crypto = CoreCrypto::default();
        crypto.kdf_params.dklen = 32;
        crypto.kdf_params.kdf = Kdf::Pbkdf2 {
            prf: Prf::default(),
            c: 10240,
        };
        crypto.kdf_params.salt = Salt::from(arr!(
        &Vec::from_hex("095a4028fa2474bb2191f9fc1d876c79a9ff76ed029aa7150d37da785a00175b",)
            .unwrap(),
        KDF_SALT_BYTES
    ));
        crypto.cipher = Cipher::default();
        crypto.cipher_text =
            Vec::from_hex("9c9e3ebbf01a512f3bea41ac6fe7676344c0da77236b38847c02718ec9b66126").unwrap();

        crypto.cipher_params.iv = Iv::from(arr!(
        &Vec::from_hex("58d54158c3e27131b0a0f2b91201aedc").unwrap(),
        CIPHER_IV_BYTES
    ));

        crypto.mac = Mac::from(arr!(
        &Vec::from_hex("83c175d2ef1229ab10eb6726500a4303ab729e6e44dfaac274fe75c870b23a63",)
            .unwrap(),
        KECCAK256_BYTES
    ));

        let exp = KeyFile {
            visible: None,
            name: Some("".to_string()),
            description: None,
            address: Address::from_str("0x4c4cfc6470a1dc26916585ef03dfec42deb936ff").unwrap(),
            uuid: Uuid::from_str("37e0d14f-7269-7ca0-4419-d7b13abfeea9").unwrap(),
            crypto: CryptoType::Core(crypto),
        };

        // just first encoding
        let key = KeyFile::decode(&file_content(path)).unwrap();

        // verify encoding & decoding full cycle logic
        let key = KeyFile::decode(&serde_json::to_string(&key).unwrap()).unwrap();

        if let CryptoType::Core(ref exp_core) = exp.crypto {
            if let CryptoType::Core(ref recv_core) = key.crypto {
                assert_eq!(key, exp);
                assert_eq!(key.visible, exp.visible);
                assert_eq!(recv_core.kdf_params, exp_core.kdf_params);
                assert_eq!(recv_core.cipher_text, exp_core.cipher_text);
                assert_eq!(recv_core.cipher_params.iv, exp_core.cipher_params.iv);
                assert_eq!(recv_core.mac, exp_core.mac);
            } else {
                assert!(false, "Invalid Crypto type")
            }
        }
    }

    #[test]
    fn should_decode_keyfile_with_address() {
        let path =
            keyfile_path("UTC--2017-03-17T10-52-08.229Z--0047201aed0b69875b24b614dda0270bcd9f11cc");

        let mut crypto = CoreCrypto::default();
        crypto.kdf_params.kdf = Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        };
        crypto.kdf_params.dklen = 32;
        crypto.kdf_params.salt = Salt::from(arr!(
        &Vec::from_hex("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4",)
            .unwrap(),
        KDF_SALT_BYTES
    ));
        crypto.cipher = Cipher::default();
        crypto.cipher_text =
            Vec::from_hex("c3dfc95ca91dce73fe8fc4ddbaed33bad522e04a6aa1af62bba2a0bb90092fa1").unwrap();

        crypto.cipher_params.iv = Iv::from(arr!(
        &Vec::from_hex("9df1649dd1c50f2153917e3b9e7164e9").unwrap(),
        CIPHER_IV_BYTES
    ));

        crypto.mac = Mac::from(arr!(
        &Vec::from_hex("9f8a85347fd1a81f14b99f69e2b401d68fb48904efe6a66b357d8d1d61ab14e5",)
            .unwrap(),
        KECCAK256_BYTES
    ));

        let exp = KeyFile {
            visible: None,
            name: None,
            description: None,
            address: Address::from_str("0x0047201aed0b69875b24b614dda0270bcd9f11cc").unwrap(),
            uuid: Uuid::from_str("f7ab2bfa-e336-4f45-a31f-beb3dd0689f3").unwrap(),
            crypto: CryptoType::Core(crypto),
        };

        // just first encoding
        let key = KeyFile::decode(&file_content(path)).unwrap();

        // verify encoding & decoding full cycle logic
        let key = KeyFile::decode(&serde_json::to_string(&key).unwrap()).unwrap();

        if let CryptoType::Core(ref exp_core) = exp.crypto {
            if let CryptoType::Core(ref recv_core) = key.crypto {
                assert_eq!(key, exp);
                assert_eq!(key.visible, exp.visible);
                assert_eq!(recv_core.kdf_params, exp_core.kdf_params);
                assert_eq!(recv_core.cipher_text, exp_core.cipher_text);
                assert_eq!(recv_core.cipher_params.iv, exp_core.cipher_params.iv);
                assert_eq!(recv_core.mac, exp_core.mac);
            } else {
                assert!(false, "Invalid Crypto type")
            }
        } else {
            assert!(false, "Invalid Crypto type")
        }
    }

    #[test]
//TODO:1 remove condition after fix for `scrypt` on Windows
    #[cfg(not(target_os = "windows"))]
    fn should_use_security_level() {
        let sec = KdfDepthLevel::Normal;
        let kf = KeyFile::new("1234567890", sec, None, None).unwrap();
        if let CryptoType::Core(ref core) = kf.crypto {
            assert_eq!(core.kdf_params.kdf, Kdf::from(sec));
        } else {
            assert!(false, "Invalid Crypto type")
        }

        let sec = KdfDepthLevel::High;
        let kf = KeyFile::new("1234567890", sec, Some("s".to_string()), None).unwrap();
        if let CryptoType::Core(ref core) = kf.crypto {
            assert_eq!(core.kdf_params.kdf, Kdf::from(sec));
        } else {
            assert!(false, "Invalid Crypto type")
        }
    }

    #[test]
    fn should_flush_to_file() {
        let kf = KeyFile::new("1234567890", KdfDepthLevel::Normal, None, None).unwrap();

        let storage = FsStorage::new(&temp_dir().as_path());

        assert!(storage.put(&kf).is_ok());
    }

    #[test]
    fn should_search_by_address_filesystem() {
        let addr = "0xc0de379b51d582e1600c76dd1efee8ed024b844a"
            .parse::<Address>()
            .unwrap();

        let storage = FsStorage::new(&keystore_path());
        let (_, kf) = storage.search_by_address(&addr).unwrap();

        assert_eq!(
            kf.uuid,
            "a928d7c2-b37b-464c-a70b-b9979d59fac4".parse().unwrap()
        );
    }

    #[test]
    fn should_search_by_address_db() {
        let addr = "0xc0de379b51d582e1600c76dd1efee8ed024b844a"
            .parse::<Address>()
            .unwrap();

        let path = keyfile_path("UTC--2017-05-30T06-16-46Z--a928d7c2-b37b-464c-a70b-b9979d59fac4");
        let key = KeyFile::decode(&file_content(path)).unwrap();

        let storage = DbStorage::new(temp_dir().as_path()).unwrap();
        storage.put(&key).unwrap();

        let (_, kf) = storage.search_by_address(&addr).unwrap();

        assert_eq!(
            kf.uuid,
            "a928d7c2-b37b-464c-a70b-b9979d59fac4".parse().unwrap()
        );
    }
}
