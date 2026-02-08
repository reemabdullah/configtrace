mod detector;
mod output;
mod patterns;

use anyhow::Result;

use crate::models::SecretReport;

/// Scan a directory for secrets and return the report data.
pub fn get_report(path: &str) -> Result<SecretReport> {
    detector::scan_directory(path)
}

/// Scan a directory for secrets and output results.
pub fn scan_for_secrets(path: &str, format: &str, output_file: Option<&str>) -> Result<bool> {
    let report = get_report(path)?;
    let has_secrets = report.total_findings > 0;

    match format {
        "json" => output::output_json(&report, output_file)?,
        _ => output::output_terminal(&report)?,
    }

    Ok(has_secrets)
}
