#![feature(test)]
extern crate jade_signer_rs;
extern crate rand;
extern crate tempdir;
extern crate test;
extern crate uuid;

use jade_signer_rs::keystore::{Kdf, KeyFile};
use jade_signer_rs::storage::{DbStorage, KeyfileStorage};
use jade_signer_rs::PrivateKey;
use std::fs::File;
use std::path::PathBuf;
use tempdir::TempDir;

pub fn temp_dir() -> PathBuf {
    let dir = TempDir::new("jade").unwrap();
    File::create(dir.path()).ok();
    dir.into_path()
}

pub fn get_keyfile() -> KeyFile {
    let pk = PrivateKey::gen();
    let kdf = Kdf::from((8, 2, 1));

    KeyFile::new_custom(pk, "1234567890", kdf, &mut rand::thread_rng(), None, None).unwrap()
}

fn time<F: FnOnce()>(f: F) -> u64 {
    let start = ::std::time::Instant::now();
    f();
    start.elapsed().as_secs()
}

fn bench_db_put_10_k() {
    let db = DbStorage::new(temp_dir().as_path()).unwrap();
    for _ in 0..10000 {
        db.put(&get_keyfile()).unwrap();
    }
}

fn bench_db_put_1_m() {
    let db = DbStorage::new(temp_dir().as_path()).unwrap();
    for _ in 0..1000000 {
        db.put(&get_keyfile()).unwrap();
    }
}

fn main() {
    println!("put 10K: {} sec", time(|| bench_db_put_10_k()));
    println!("put 1M: {} sec", time(|| bench_db_put_1_m()));
}
