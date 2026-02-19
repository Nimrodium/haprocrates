use clap::Parser;

mod cli;
mod crypto;
mod database;
fn main() {
    let args = cli::CliArguments::parse();
    println!("Hello, world!");
}
