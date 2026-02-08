use anyhow::Result;
use clap::{Parser, Subcommand};

mod diff;
mod git;
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
    /// Generate a unified audit report (inventory, secrets, policy, git)
    Report {
        /// Path to directory to audit
        path: String,
        /// Path to policy file for policy evaluation
        #[arg(long)]
        policy: Option<String>,
        /// Output format: text, json, or markdown
        #[arg(long, default_value = "text")]
        format: String,
        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
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
    /// Analyze config changes across git history
    Git {
        #[command(subcommand)]
        action: GitAction,
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

#[derive(Subcommand)]
enum GitAction {
    /// Show config change history across git commits
    Log {
        /// Path filter: only show changes to configs under this path
        path: Option<String>,
        /// Maximum number of commits to analyze
        #[arg(long, default_value = "10")]
        limit: usize,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
        /// Path to policy file for historical audit
        #[arg(long)]
        policy: Option<String>,
    },
    /// Compare config files between two git refs at the key level
    Diff {
        /// First git ref (commit, branch, tag)
        ref1: String,
        /// Second git ref (commit, branch, tag)
        ref2: String,
        /// Path filter: only compare configs under this path
        path: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
        /// Path to policy file for policy audit
        #[arg(long)]
        policy: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, out } => scan::scan(&path, &out)?,
        Commands::Diff { old, new } => diff::diff(&old, &new)?,
        Commands::Report {
            path,
            policy,
            format,
            output,
        } => {
            let is_fail =
                report::generate_report(&path, policy.as_deref(), &format, output.as_deref())?;
            if is_fail {
                std::process::exit(1);
            }
        }
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
        Commands::Git { action } => match action {
            GitAction::Log {
                path,
                limit,
                format,
                output,
                policy,
            } => {
                let has_violations = git::git_log(
                    path.as_deref(),
                    limit,
                    &format,
                    output.as_deref(),
                    policy.as_deref(),
                )?;
                if has_violations {
                    std::process::exit(1);
                }
            }
            GitAction::Diff {
                ref1,
                ref2,
                path,
                format,
                output,
                policy,
            } => {
                let has_violations = git::git_diff(
                    &ref1,
                    &ref2,
                    path.as_deref(),
                    &format,
                    output.as_deref(),
                    policy.as_deref(),
                )?;
                if has_violations {
                    std::process::exit(1);
                }
            }
        },
    }
    Ok(())
}
