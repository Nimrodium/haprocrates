// secret file management
use crate::{
    constant::MASTER_SIZE,
    crypto::{DecryptedFile, generate_random_series},
};
use anyhow::Result;
use rand::{self, RngExt};
use std::path::{Path, PathBuf};
pub struct Master {
    master_name: String,
    master_data: Vec<u8>,
}

impl Master {
    pub fn open(name: &str) -> Result<Self> {}

    pub fn new(name: &str) -> Result<Master> {
        let master_data = generate_random_series(MASTER_SIZE);
        Ok(Self {
            master_name: name.to_string(),
            master_data: master_data,
        })
    }
}
