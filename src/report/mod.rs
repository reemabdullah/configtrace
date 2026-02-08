mod models;
mod output;

use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

use crate::utils::{hash_file, is_config};
use models::{AuditReport, InventoryEntry, OverviewSection, RiskLevel};

/// Generate a unified audit report. Returns true if risk level is Fail.
pub fn generate_report(
    path: &str,
    policy_path: Option<&str>,
    format: &str,
    output_file: Option<&str>,
) -> Result<bool> {
    let report = collect_report(path, policy_path)?;
    let is_fail = report.risk_level == RiskLevel::Fail;

    match format {
        "json" => output::output_json(&report, output_file)?,
        "markdown" | "md" => output::output_markdown(&report, output_file)?,
        _ => output::output_terminal(&report)?,
    }

    Ok(is_fail)
}

fn collect_report(path: &str, policy_path: Option<&str>) -> Result<AuditReport> {
    // 1. Collect config inventory
    let mut inventory = Vec::new();
    let mut yaml_count = 0;
    let mut json_count = 0;
    let mut toml_count = 0;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if !file_path.is_file() || !is_config(file_path) {
            continue;
        }

        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        match ext.as_str() {
            "yaml" | "yml" => yaml_count += 1,
            "json" => json_count += 1,
            "toml" => toml_count += 1,
            _ => {}
        }

        let hash = hash_file(file_path).unwrap_or_else(|_| "error".to_string());
        inventory.push(InventoryEntry {
            path: file_path.display().to_string(),
            hash,
            format: ext,
        });
    }

    inventory.sort_by(|a, b| a.path.cmp(&b.path));
    let total_files = inventory.len();

    let overview = OverviewSection {
        generated_at: chrono::Utc::now().to_rfc3339(),
        path: path.to_string(),
        total_files,
        yaml_count,
        json_count,
        toml_count,
    };

    // 2. Secret scan
    let secrets = match crate::secrets::get_report(path) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("Warning: Secret scan failed: {}", e);
            None
        }
    };

    // 3. Policy evaluation (if policy provided)
    let policy = if let Some(pp) = policy_path {
        match crate::policy::loader::load_policy(Path::new(pp)) {
            Ok(policy_file) => {
                match crate::policy::evaluator::evaluate_policy(path, &policy_file) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("Warning: Policy evaluation failed: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to load policy: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 4. Git change history
    let git_changes = match crate::git::collect_log(None, 5) {
        Ok(r) if !r.commits.is_empty() => Some(r),
        Ok(_) => None,
        Err(_) => None, // Skip silently if not a git repo or other error
    };

    // 5. Compute risk level
    let has_critical_secrets = secrets.as_ref().is_some_and(|s| s.critical_count > 0);
    let has_critical_policy = policy.as_ref().is_some_and(|p| p.critical_count > 0);
    let has_any_secrets = secrets.as_ref().is_some_and(|s| s.total_findings > 0);
    let has_any_violations = policy.as_ref().is_some_and(|p| p.total_violations > 0);

    let risk_level = if has_critical_secrets || has_critical_policy {
        RiskLevel::Fail
    } else if has_any_secrets || has_any_violations {
        RiskLevel::Warn
    } else {
        RiskLevel::Pass
    };

    let mut summary_parts = Vec::new();
    if let Some(s) = &secrets {
        if s.total_findings > 0 {
            summary_parts.push(format!("{} secrets found", s.total_findings));
        }
    }
    if let Some(p) = &policy {
        if p.total_violations > 0 {
            summary_parts.push(format!("{} policy violations", p.total_violations));
        }
    }

    let risk_summary = if summary_parts.is_empty() {
        "No issues found".to_string()
    } else {
        summary_parts.join(", ")
    };

    Ok(AuditReport {
        overview,
        inventory,
        secrets,
        policy,
        git_changes,
        risk_level,
        risk_summary,
    })
}
