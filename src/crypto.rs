use crate::{
    cli::get_user_input,
    constant::{KEY_SIZE, NONCE_SIZE, SALT_SIZE},
    master::MasterKey,
};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use anyhow::Result;
use argon2::password_hash::PasswordHasher;
use argon2::{Argon2, password_hash::SaltString};
use std::{
    fs::{File, rename},
    io::{Read, Write},
    path::{Path, PathBuf},
};

type FileNonce = Nonce<aes_gcm::aead::consts::U12>;
type Password = [u8; KEY_SIZE];
type PasswordSalt = [u8; SALT_SIZE];

// handles central hashing function and supporting cryptographic operations
pub fn hash_password(content: &[u8], salt: &[u8]) -> Result<String> {
    // Argon2::default().hash_password(content, salt)?.to_string()
    let salt = SaltString::from_b64(&base64_encode(salt))
        .map_err(|e| anyhow::anyhow!("failed to encode salt as base64: {e}"))?;
    Ok(Argon2::default()
        .hash_password(
            content,
            &salt, // &SaltString::encode_b64(&salt)
                  //     .map_err(|e| anyhow::anyhow!("failed to encode salt as base64: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?
        .serialize()
        .to_string())
}
pub fn base64_encode(bytes: &[u8]) -> String {
    BASE64_STANDARD_NO_PAD.encode(bytes)
}
pub fn generate_random_series(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
// // the Key struct
// pub struct MasterKeyPassword {
//     name: String,
//     bytes: Password,
// }
// impl MasterKeyPassword {
//     fn get_key(&self) -> Key<Aes256Gcm> {
//         Key::<Aes256Gcm>::from_iter(self.bytes)
//     }
//     fn new(name: &str, salt_directory: &Path) -> Result<Self> {
//         let password = get_user_input("enter new masterkey password")?;
//         let salt = Self::new_salt();
//         Self::save_salt(name, &salt, salt_directory)?;
//         Self::from_password(name, &password, &salt)
//     }
//     fn new_salt() -> Salt {
//         generate_random_series(SALT_SIZE).try_into().unwrap()
//     }
//     fn open_salt(salt_directory: &Path, name: &str) -> Result<Salt> {
//         let path = salt_directory.with_file_name(name);
//         let mut file = File::open(&path)?;
//         let mut buf = Vec::new();
//         file.read_to_end(&mut buf)?;
//         buf.try_into().map_err(|_| {
//             anyhow::anyhow!(format!(
//                 "salt \"{:?}\" is not a valid salt, not the correct length of {SALT_SIZE} bytes:",
//                 &path
//             ))
//         })
//     }
//     fn save_salt(name: &str, salt: &Salt, salt_directory: &Path) -> Result<()> {
//         let path = salt_directory.with_file_name(name);
//         if !path.exists() {
//             let mut file = File::create(path)?;
//             file.write(salt)?;
//             Ok(())
//         } else {
//             Err(anyhow::anyhow!(format!("{:?}", path)))
//         }
//     }
//     fn from_password(name: &str, password: &str, salt: &Salt) -> Result<Self> {
//         let mut key = [1; KEY_SIZE];
//         Argon2::default()
//             .hash_password_into(password.as_bytes(), salt, &mut key)
//             .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;
//         Ok(Self {
//             name: name.to_string(),
//             bytes: key,
//         })
//     }

//     fn prompt(name: &str, salt_directory: &Path) -> Result<Self> {
//         let salt = Self::open_salt(salt_directory, name)?;
//         let password = get_user_input("enter encryption password for master \"{name}\": ")?;
//         Self::from_password(name, &password, &salt)
//     }
// }

// fn parse_nonce_salt_file(path: &Path) -> Result<(Salt, KeyNonce)> {
//     let mut file = File::open(path)?;
//     let mut buf = Vec::new();
//     file.read_to_end(&mut buf);
//     if buf.len() != SALT_SIZE + NONCE_SIZE {
//         return Err(anyhow::anyhow!(
//             "nonce_salt file {path:?} not the correct length of {}",
//             SALT_SIZE + NONCE_SIZE
//         ));
//     }
//     let salt: Salt = buf
//         .clone()
//         .into_iter()
//         .take(SALT_SIZE)
//         .collect::<Vec<u8>>()
//         .try_into()
//         .unwrap();
//     let nonce: KeyNonce = KeyNonce::from_iter(buf.into_iter().skip(SALT_SIZE).take(NONCE_SIZE));
//     Ok((salt, nonce))
// }
/// encryption format password-hash:nonce:encrypted_data

pub struct CryptoFileHandle {
    path: PathBuf,
    password: String,
    // salt: Salt,
    // nonce: KeyNonce,
}
impl CryptoFileHandle {
    /// create a new encrypted file
    pub fn create(path: &Path, password: Option<&str>) -> Result<Self> {
        // let salt = Self::new_salt();
        let password = if let Some(pw) = password {
            pw.to_string()
        } else {
            get_user_input(&format!("enter new password for \"{path:?}\""))?
        };
        Ok(Self {
            password,
            // salt,
            path: path.to_owned(),
            // nonce: Self::new_nonce(),
        })
    }
    pub fn decrypt(path: &Path, password: Option<&str>) -> Result<(Self, Vec<u8>)> {
        let password = if let Some(pw) = password {
            pw.to_string()
        } else {
            get_user_input(&format!("enter password for \"{path:?}\""))?
        };
        let mut file = File::open(path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;
        let (salt, nonce, encrypted) = Self::parse(file_data);
        let handle = Self {
            path: path.to_owned(),
            password,
        };
        let decrypted = handle.decrypt_data(encrypted, &nonce, &salt)?;
        Ok((handle, decrypted))
    }
    pub fn encrypt(self, decrypted: &[u8]) -> Result<()> {
        let nonce = Self::new_nonce();
        let salt = Self::new_salt();
        let encrypted = self.encrypt_data(decrypted, &nonce, &salt)?;
        let file_data = Self::bundle(salt, nonce, encrypted);
        let tmp_path = self.path.with_added_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(&file_data)?;
        rename(tmp_path, self.path)?;
        Ok(())
    }

    fn parse(file_data: Vec<u8>) -> (PasswordSalt, FileNonce, Vec<u8>) {
        // extract salt, nonce, and encrypted data.
        let mut iterator = file_data.into_iter();
        let salt = Self::salt_from(iterator.by_ref().take(SALT_SIZE).collect::<Vec<u8>>());
        let nonce = FileNonce::from_iter(iterator.by_ref().take(NONCE_SIZE));
        let encrypted = iterator.collect();
        (salt, nonce, encrypted)
    }

    fn bundle(salt: PasswordSalt, nonce: FileNonce, encrypted: Vec<u8>) -> Vec<u8> {
        salt.into_iter()
            .chain(nonce.into_iter().chain(encrypted.into_iter()))
            .collect()
    }
    fn decrypt_data(
        &self,
        encrypted: Vec<u8>,
        nonce: &FileNonce,
        salt: &PasswordSalt,
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key(salt)?);
        cipher.decrypt(&nonce, encrypted.as_ref()).map_err(|e| {
            anyhow::anyhow!(format!("could not decrypt file \"{:?}\": {e}", self.path))
        })
    }
    fn encrypt_data(
        &self,
        decrypted: &[u8],
        nonce: &FileNonce,
        salt: &PasswordSalt,
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key(salt)?);
        cipher.encrypt(nonce, decrypted).map_err(|e| {
            anyhow::anyhow!(format!("could not encrypt file \"{:?}\": {e}", self.path))
        })
    }
    fn key(&self, salt: &PasswordSalt) -> Result<Key<Aes256Gcm>> {
        Ok(Key::<Aes256Gcm>::from_iter(Self::hash_password(
            &self.password,
            salt,
        )?))
    }
    // fn prompt_password(msg: &str, salt: &PasswordSalt) -> Result<Password> {
    //     let response = get_user_input(msg)?;
    //     Self::hash_password(&response, salt)
    // }
    fn hash_password(plain_text: &str, salt: &PasswordSalt) -> Result<Password> {
        let mut password = [1; KEY_SIZE];
        Argon2::default()
            .hash_password_into(plain_text.as_bytes(), salt, &mut password)
            .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;
        Ok(password)
    }
    fn new_salt() -> PasswordSalt {
        Self::salt_from(generate_random_series(SALT_SIZE))
    }
    fn salt_from(bytes: Vec<u8>) -> PasswordSalt {
        PasswordSalt::try_from(bytes).expect("salt read is not the correct length!")
    }
    fn new_nonce() -> FileNonce {
        Aes256Gcm::generate_nonce(OsRng)
    }
}
#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, remove_file};

    use crate::constant::TESTS_DIRECTORY;

    use super::*;
    #[test]
    fn test_crypto_file_handle_data_integrity() -> Result<()> {
        let tests_directory = PathBuf::from(TESTS_DIRECTORY);
        create_dir_all(&tests_directory)?;
        let test_file_path = tests_directory.join("crypto_file_handle_data_integrity.enc");
        let password = Some("password123");
        // let password = None;
        let data = b"This is a test of the CryptoFileHandle's integrity of data during creation, encryption, and then decryption. reading back this file should be the same".to_vec();
        let new_file = CryptoFileHandle::create(&test_file_path, password.clone())?;
        new_file.encrypt(&data)?;

        let (handle, decrypted) = CryptoFileHandle::decrypt(&test_file_path, password.clone())?;
        assert_eq!(decrypted, data);
        // write back read data.
        handle.encrypt(&decrypted)?;
        // test to see if decrypted data that has been reencrypted can then be recovered again
        let (_, decrypted) = CryptoFileHandle::decrypt(&test_file_path, password)?;
        assert_eq!(decrypted, data);
        remove_file(test_file_path)?;
        Ok(())
    }
}

// pub struct DecryptedFile {
//     path: PathBuf,
//     key: MasterKeyPassword,
//     nonce: KeyNonce,
//     data: Vec<u8>,
// }
// fn build_nonce_salt_file(salt: &Salt, nonce: &KeyNonce) -> Vec<u8> {
//     // let nonce_bytes = nonce.to_vec();
//     let mut bytes = salt.to_vec();
//     bytes.extend(nonce);
//     bytes
// }
// impl DecryptedFile {
//     pub fn create(
//         path: &Path,
//         salt_directory: &Path,
//         key: MasterKeyPassword,
//         salt: Salt,
//         nonce: KeyNonce,
//     ) -> Result<Self> {
//         let mut file = File::create(path)?;

//         todo!()
//     }
//     pub fn decrypt(path: &Path, key: MasterKeyPassword, nonce: KeyNonce) -> Result<DecryptedFile> {
//         let mut file = File::open(path)?;
//         let cipher = Aes256Gcm::new(&key.get_key());
//         let mut cipher_text = Vec::new();
//         file.read_to_end(&mut cipher_text)?;

//         let decrypted_text = cipher
//             .decrypt(&nonce, cipher_text.as_ref())
//             .map_err(|e| anyhow::anyhow!(format!("could not decrypt file \"{:?}\": {e}", path)))?;
//         Ok(Self {
//             path: path.to_owned(),
//             key: key,
//             nonce: nonce,
//             data: decrypted_text,
//         })
//     }
//     pub fn encrypt(self, key: Key<Aes256Gcm>, data: Vec<u8>) -> Result<()> {
//         let cipher = Aes256Gcm::new(&key);
//         let cipher_text = cipher.encrypt(&self.nonce, data.as_ref()).map_err(|e| {
//             anyhow::anyhow!(format!("could not encrypt file \"{:?}\": {e}", self.path))
//         })?;

//         //Writing data to file.
//         let tmp_path = self.path.with_added_extension("tmp");
//         let mut file = File::create(&tmp_path)?;
//         file.write(&cipher_text)?;
//         rename(tmp_path, self.path);
//         Ok(())
//     }
//     pub fn read<'a>(&'a self) -> &'a [u8] {
//         &self.data
//     }
// }
