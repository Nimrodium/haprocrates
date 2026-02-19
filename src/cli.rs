use anyhow::Result;
use clap::{Args, Parser, Subcommand};
macro_rules! site_username_pair {
    () => {
        #[arg(short, long)]
        site: String,
        #[arg(short, long)]
        username: String
    };
}
#[derive(Args, Debug, Clone)]
struct SiteUsernamePair {
    #[arg(short, long)]
    site: String,
    #[arg(short, long)]
    username: String,
}
#[derive(Parser, Debug, Clone)]
#[command(name = "Haprocrates", about = "Deterministic Password Manager")]
pub struct CliArguments {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    iteration: Option<usize>,
    #[arg(short, long)]
    database: Option<String>,
    #[arg(long)]
    no_agent: bool,
    #[arg(long)]
    no_vault: bool,
    #[arg(long)]
    key: Option<String>,
}
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Compute the password for a site-username pair.
    Derive {
        #[command(flatten)]
        pair: SiteUsernamePair,
    },
    /// Export a site-username pair along with its computed password.
    Export {
        #[command(flatten)]
        pair: SiteUsernamePair,
    },
    /// Share a computed password to another device.
    Share {
        #[command(subcommand)]
        mode: ShareMode,
        #[command(flatten)]
        pair: SiteUsernamePair,
    },
    /// Generate a new Master-Secret-Key.
    GenerateMaster {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Open the encrypted vault
    Show {},
    ///
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    }, // AllowDiskState {},
       // DisableDiskState {},
}
#[derive(Subcommand, Clone, Debug)]
enum VaultCommand {
    Remove {
        #[command(flatten)]
        pair: SiteUsernamePair,
    },
    Add {
        #[command(flatten)]
        pair: SiteUsernamePair,
    },
    List {
        #[command(flatten)]
        pair: Option<SiteUsernamePair>,
    },
    Enable,
    Disable,
}
#[derive(Subcommand, Clone, Debug)]
enum ShareMode {
    Http,
    Qr,
}
pub struct EnvironmentVariables {
    password: Option<String>,
    database: String,
    auth_timeout: u32,
}
impl EnvironmentVariables {
    pub fn new() -> Result<Self> {
        todo!()
    }
}
