mod evaluator;
mod loader;
pub mod models;
mod output;
mod parser;

use anyhow::Result;
use std::path::Path;

/// Check configs against a policy file. Returns true if violations were found.
pub fn check_policy(
    path: &str,
    policy_path: &str,
    format: &str,
    output_file: Option<&str>,
) -> Result<bool> {
    let policy = loader::load_policy(Path::new(policy_path))?;
    let report = evaluator::evaluate_policy(path, &policy)?;
    let has_violations = report.total_violations > 0;

    match format {
        "json" => output::output_json(&report, output_file)?,
        _ => output::output_terminal(&report)?,
    }

    Ok(has_violations)
}

/// Validate a policy file without running checks.
pub fn validate_policy_file(policy_path: &str) -> Result<()> {
    let policy = loader::load_policy(Path::new(policy_path))?;
    println!("Policy '{}' is valid ({} rules)", policy.name, policy.rules.len());
    for rule in &policy.rules {
        println!(
            "  - [{}] {} ({})",
            rule.id,
            rule.description.as_deref().unwrap_or(""),
            rule.severity
        );
    }
    Ok(())
}
