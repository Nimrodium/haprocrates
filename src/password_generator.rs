use crate::{
    crypto::{base64_encode, hash_password},
    master::MasterKey,
};
use anyhow::Result;
use base64::{Engine, prelude::BASE64_STANDARD};
pub struct Password {}
pub struct Credentials {
    site_name: String,
    username: String,
}
impl Credentials {
    pub fn new(site_name: &str, username: &str) -> Self {
        Self {
            site_name: normalize(site_name),
            username: normalize(username),
        }
    }
    // pub fn generate_password(&self, master: &MasterKey) -> Password {}
    fn generate_password(&self, master: &MasterKey) -> Result<String> {
        Ok(hash_password(
            (self.site_name.clone() + &self.username).as_bytes(),
            master,
        )?)
    }
}
fn normalize(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}
#[cfg(test)]
mod tests {
    use std::{
        fs::{create_dir_all, remove_file},
        path::PathBuf,
    };

    use crate::{
        constant::TESTS_DIRECTORY,
        master::{new_master_key, open_master_key},
    };

    use super::*;
    #[test]
    fn test_password_reproducibility() -> Result<()> {
        let tests_directory = PathBuf::from(TESTS_DIRECTORY);
        create_dir_all(&tests_directory)?;
        let master_path = tests_directory.join("test_password_reproducibility.master");
        let password = Some("password123");
        let credentials = Credentials::new("https://example.com", "user");
        let master_1 = new_master_key(&master_path, password)?;
        let generated_password_1 = credentials.generate_password(&master_1)?;
        // read master from disk and try to create the same generated password
        let master_2 = open_master_key(&master_path, password)?;
        let generated_password_2 = credentials.generate_password(&master_2)?;
        println!("{generated_password_1}");
        assert_eq!(generated_password_1, generated_password_2);
        remove_file(master_path)?;
        Ok(())
    }
}
