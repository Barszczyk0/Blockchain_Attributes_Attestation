use attributes_attestation::cli::Cli;
use clap::Parser;

fn main() {
    if let Err(s) = Cli::parse().run() {
        eprintln!("{s}");
    }
}
