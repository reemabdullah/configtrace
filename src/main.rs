use anyhow::Result;
use clap::{Parser, Subcommand};

mod diff;
mod models;
mod report;
mod scan;
mod secrets;
mod utils;

#[derive(Parser)]
#[command(name = "configtrace", about = "Track & audit configuration changes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory and produce a snapshot (hashes of YAML/JSON/TOML)
    Scan {
        path: String,
        #[arg(long, default_value = "snapshot.json")]
        out: String,
    },
    /// Compare two snapshots and print a simple diff
    Diff { old: String, new: String },
    /// Generate a Markdown report from a snapshot
    Report {
        snapshot: String,
        #[arg(long, default_value = "report.md")]
        out: String,
    },
    /// Scan for secrets in configuration files
    Secrets {
        path: String,
        #[arg(long, default_value = "text")]
        format: String,
        #[arg(long)]
        output: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, out } => scan::scan(&path, &out)?,
        Commands::Diff { old, new } => diff::diff(&old, &new)?,
        Commands::Report { snapshot, out } => report::report(&snapshot, &out)?,
        Commands::Secrets {
            path,
            format,
            output,
        } => {
            let has_secrets = secrets::scan_for_secrets(&path, &format, output.as_deref())?;
            if has_secrets {
                std::process::exit(1); // Exit with code 1 if secrets found
            }
        }
    }
    Ok(())
}
