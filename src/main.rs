use crate::cli::user_confirm;
use anyhow::Result;
use clap::Parser;
mod cli;
mod constant;
mod crypto;
mod master;
mod password_generator;
mod storage;
mod vault;
fn main() -> Result<()> {
    let args = cli::CliArguments::parse();
    println!("{}", user_confirm("Haprocrates")?);
    Ok(())
}
