use crate::constant::{
    APPLICATION_NAME, MASTER_DIRECTORY, MASTER_EXTENSION, MASTER_KEY_SALT_DIRECTORY,
    MASTER_KEY_SALT_EXTENSION, VAULT_FILENAME,
};
use anyhow::Result;
use std::{env, fs::File, path::PathBuf};

pub struct Storage {
    /// platform specific
    /// * Linux:    `~/.local/state/haprocrates/`
    /// * Windows:  `%APPDATA%\haprocrates\`
    /// * macOS:      `~/Library/Application Support/haprocrates/`
    application_root: PathBuf,
    ///
    password: Option<String>,
}
impl Storage {
    pub fn new() -> Result<Self> {
        let application_root = if let Some(app_root) = env::var("HAPROCRATES_DATABASE").ok() {
            PathBuf::from(app_root)
        } else {
            Self::find_app_root()
        };
        let password = if let Some(password) = env::var("HAPROCRATES_PASSWORD").ok() {
            Some(password)
        } else if let Some(password_file) = env::var("HAPROCRATES_PASSWORD_FILE").ok() {
            let mut file = File::open(password_file)?;
            let mut password = String::new();
            file.read_to_string(&mut password)?;
            Some(password)
        } else {
            None
        };
        Ok(Self {
            application_root,
            password,
        })
    }
    fn find_app_root() -> PathBuf {
        fn get_home() -> PathBuf {
            PathBuf::from(
                env::var("HOME").expect("your unix environment is very wrong. $HOME is not set."),
            )
        }
        let application_directory = PathBuf::from(APPLICATION_NAME);
        if cfg!(target_os = "windows") {
            PathBuf::from(
                env::var("APPDATA")
                    .expect("your windows environment is very wrong. %APPDATA% is not set."),
            )
            .join(application_directory)
        } else if cfg!(target_os = "macos") {
            get_home()
                .join(PathBuf::from("Library/Application Support/"))
                .join(application_directory)
        } else if cfg!(target_family = "unix") {
            let state_home = if let Some(state_home) = env::var("XDG_STATE_HOME").ok() {
                PathBuf::from(state_home)
            } else {
                get_home().join(".local/state")
            };
            state_home.join(application_directory)
        } else {
            panic!("unknown OS! {APPLICATION_NAME} has no idea where to store state!")
        }
    }
    pub fn get_vault_file(&self) -> PathBuf {
        self.application_root.with_file_name(VAULT_FILENAME)
    }
    pub fn get_master_salt_pair(&self, name: &str) -> (PathBuf, PathBuf) {
        (self.get_master(name), self.get_master_key_salt(name))
    }
    pub fn get_master(&self, name: &str) -> PathBuf {
        let master_path = PathBuf::from(MASTER_DIRECTORY)
            .join(PathBuf::from(name).with_added_extension(MASTER_EXTENSION));
        self.application_root.join(master_path)
    }
    pub fn get_master_key_salt(&self, name: &str) -> PathBuf {
        let master_salts_path = PathBuf::from(MASTER_KEY_SALT_DIRECTORY)
            .join(PathBuf::from(name).with_added_extension(MASTER_KEY_SALT_EXTENSION));
        self.application_root.join(master_salts_path)
    }
}
