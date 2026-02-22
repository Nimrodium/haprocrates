use crate::{
    cli::get_user_input,
    constant::{KEY_SIZE, MASTER_SIZE, NONCE_SIZE, SALT_SIZE},
};
use aes_gcm::{
    AeadCore, Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use argon2::Argon2;
use rand::{self, RngExt};
use std::{
    fs::{File, rename},
    io::{Read, Write},
    path::{Path, PathBuf},
};

type KeyNonce = Nonce<aes_gcm::aead::consts::U12>;
type MasterKeyPasswordHash = [u8; KEY_SIZE];
type Salt = [u8; SALT_SIZE];

// handles central hashing function and supporting cryptographic operations
pub fn hash_password(site: &str, username: &str, secret: &[u8]) -> String {
    todo!()
}
pub fn generate_random_series(size: usize) -> Vec<u8> {
    rand::rng().random_iter().take(size).collect()
}
// the Key struct
pub struct MasterKeyPassword {
    name: String,
    bytes: MasterKeyPasswordHash,
}
impl MasterKeyPassword {
    fn get_key(&self) -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_iter(self.bytes)
    }
    fn new(name: &str, salt_directory: &Path) -> Result<Self> {
        let password = get_user_input("enter new masterkey password")?;
        let salt = Self::new_salt();
        Self::save_salt(name, &salt, salt_directory)?;
        Self::from_password(name, &password, &salt)
    }
    fn new_salt() -> Salt {
        generate_random_series(SALT_SIZE).try_into().unwrap()
    }
    fn open_salt(salt_directory: &Path, name: &str) -> Result<Salt> {
        let path = salt_directory.with_file_name(name);
        let mut file = File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        buf.try_into().map_err(|_| {
            anyhow::anyhow!(format!(
                "salt \"{:?}\" is not a valid salt, not the correct length of {SALT_SIZE} bytes:",
                &path
            ))
        })
    }
    fn save_salt(name: &str, salt: &Salt, salt_directory: &Path) -> Result<()> {
        let path = salt_directory.with_file_name(name);
        if !path.exists() {
            let mut file = File::create(path)?;
            file.write(salt)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!("{:?}", path)))
        }
    }
    fn from_password(name: &str, password: &str, salt: &Salt) -> Result<Self> {
        let mut key = [1; KEY_SIZE];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;
        Ok(Self {
            name: name.to_string(),
            bytes: key,
        })
    }

    fn prompt(name: &str, salt_directory: &Path) -> Result<Self> {
        let salt = Self::open_salt(salt_directory, name)?;
        let password = get_user_input("enter encryption password for master \"{name}\": ")?;
        Self::from_password(name, &password, &salt)
    }
}

fn parse_nonce_salt_file(path: &Path) -> Result<(Salt, KeyNonce)> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf);
    if buf.len() != SALT_SIZE + NONCE_SIZE {
        return Err(anyhow::anyhow!(
            "nonce_salt file {path:?} not the correct length of {}",
            SALT_SIZE + NONCE_SIZE
        ));
    }
    let salt: Salt = buf
        .clone()
        .into_iter()
        .take(SALT_SIZE)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let nonce: KeyNonce = KeyNonce::from_iter(buf.into_iter().skip(SALT_SIZE).take(NONCE_SIZE));
    Ok((salt, nonce))
}

pub struct DecryptedFile {
    path: PathBuf,
    key: MasterKeyPassword,
    nonce: KeyNonce,
    data: Vec<u8>,
}
fn build_nonce_salt_file(salt: &Salt, nonce: &KeyNonce) -> Vec<u8> {
    // let nonce_bytes = nonce.to_vec();
    let mut bytes = salt.to_vec();
    bytes.extend(nonce);
    bytes
}
impl DecryptedFile {
    pub fn create(
        path: &Path,
        salt_directory: &Path,
        key: MasterKeyPassword,
        salt: Salt,
        nonce: KeyNonce,
    ) -> Result<Self> {
        let mut file = File::create(path)?;

        todo!()
    }
    pub fn decrypt(path: &Path, key: MasterKeyPassword, nonce: KeyNonce) -> Result<DecryptedFile> {
        let mut file = File::open(path)?;
        let cipher = Aes256Gcm::new(&key.get_key());
        let mut cipher_text = Vec::new();
        file.read_to_end(&mut cipher_text)?;

        let decrypted_text = cipher
            .decrypt(&nonce, cipher_text.as_ref())
            .map_err(|e| anyhow::anyhow!(format!("could not decrypt file \"{:?}\": {e}", path)))?;
        Ok(Self {
            path: path.to_owned(),
            key: key,
            nonce: nonce,
            data: decrypted_text,
        })
    }
    pub fn encrypt(self, key: Key<Aes256Gcm>, data: Vec<u8>) -> Result<()> {
        let cipher = Aes256Gcm::new(&key);
        let cipher_text = cipher.encrypt(&self.nonce, data.as_ref()).map_err(|e| {
            anyhow::anyhow!(format!("could not encrypt file \"{:?}\": {e}", self.path))
        })?;

        //Writing data to file.
        let tmp_path = self.path.with_added_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        file.write(&cipher_text)?;
        rename(tmp_path, self.path);
        Ok(())
    }
    pub fn read<'a>(&'a self) -> &'a [u8] {
        &self.data
    }
}
