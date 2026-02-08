use serde::Serialize;

use crate::git::models::GitLogReport;
use crate::models::SecretReport;
use crate::policy::models::PolicyReport;

/// Overall risk assessment.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Pass => write!(f, "PASS"),
            RiskLevel::Warn => write!(f, "WARN"),
            RiskLevel::Fail => write!(f, "FAIL"),
        }
    }
}

/// Summary statistics for the report overview.
#[derive(Debug, Serialize)]
pub struct OverviewSection {
    pub generated_at: String,
    pub path: String,
    pub total_files: usize,
    pub yaml_count: usize,
    pub json_count: usize,
    pub toml_count: usize,
}

/// A single file in the config inventory.
#[derive(Debug, Serialize)]
pub struct InventoryEntry {
    pub path: String,
    pub hash: String,
    pub format: String,
}

/// The unified audit report combining all analysis results.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub overview: OverviewSection,
    pub inventory: Vec<InventoryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_changes: Option<GitLogReport>,
    pub risk_level: RiskLevel,
    pub risk_summary: String,
}
