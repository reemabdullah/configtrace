use anyhow::Result;
use clap::{Parser, Subcommand};

mod diff;
mod models;
mod policy;
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
    /// Check configuration files against a policy
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate configs against a policy file
    Check {
        /// Path to directory or file to check
        path: String,
        /// Path to the policy YAML file
        #[arg(long)]
        policy: String,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
    },
    /// Validate a policy file without running checks
    Validate {
        /// Path to the policy YAML file
        policy: String,
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
                std::process::exit(1);
            }
        }
        Commands::Policy { action } => match action {
            PolicyAction::Check {
                path,
                policy: policy_path,
                format,
                output,
            } => {
                let has_violations =
                    policy::check_policy(&path, &policy_path, &format, output.as_deref())?;
                if has_violations {
                    std::process::exit(1);
                }
            }
            PolicyAction::Validate {
                policy: policy_path,
            } => {
                policy::validate_policy_file(&policy_path)?;
            }
        },
    }
    Ok(())
}
