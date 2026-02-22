// secret file management
use crate::{
    constant::MASTER_SIZE,
    crypto::{CryptoFileHandle, generate_random_series},
};
use anyhow::Result;
use std::path::Path;
pub type MasterKey = [u8; MASTER_SIZE];

pub fn open_master_key(path: &Path, password: Option<&str>) -> Result<MasterKey> {
    let (_, key) = CryptoFileHandle::decrypt(path, password)?;
    key.try_into()
        .map_err(|_| anyhow::anyhow!("master key \"{path:?}\" is not the correct length!"))
}
pub fn new_master_key(path: &Path, password: Option<&str>) -> Result<MasterKey> {
    let handle = CryptoFileHandle::create(path, password)?;
    let key = generate_new_master_key();
    handle.encrypt(&key)?;
    Ok(key)
}
fn generate_new_master_key() -> MasterKey {
    MasterKey::try_from(generate_random_series(MASTER_SIZE)).unwrap()
}
