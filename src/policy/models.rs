use serde::{Deserialize, Serialize};

/// Four-level severity for policy violations.
/// Separate from secrets::Severity to allow independent evolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for PolicySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicySeverity::Critical => write!(f, "CRITICAL"),
            PolicySeverity::High => write!(f, "HIGH"),
            PolicySeverity::Medium => write!(f, "MEDIUM"),
            PolicySeverity::Low => write!(f, "LOW"),
        }
    }
}

fn default_severity() -> PolicySeverity {
    PolicySeverity::Medium
}

// ========== Policy File Definition (deserialized from YAML) ==========

/// Top-level policy file structure.
#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<RuleDefinition>,
}

/// A single rule within a policy file.
#[derive(Debug, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub description: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: PolicySeverity,
    /// Glob pattern for which config files this rule applies to.
    /// If omitted, the rule applies to all config files.
    pub pattern: Option<String>,
    pub check: CheckDefinition,
}

/// The check to perform, represented as a tagged enum.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckDefinition {
    /// A key must exist in the config.
    RequiredKey { key: String },
    /// A key must NOT exist in the config.
    ForbiddenKey { key: String },
    /// A key's value must match a regex pattern.
    ValueMatch { key: String, regex: String },
    /// A key's value must be one of the allowed values.
    ValueEnum { key: String, values: Vec<String> },
    /// A specific key-value combination must not exist.
    ForbiddenValue { key: String, value: String },
}

// ========== Evaluation Results (for output) ==========

/// A single violation produced when a rule check fails.
#[derive(Debug, Serialize)]
pub struct Violation {
    pub rule_id: String,
    pub rule_description: Option<String>,
    pub severity: PolicySeverity,
    pub file: String,
    pub key: String,
    pub message: String,
}

/// Violations grouped by file.
#[derive(Debug, Serialize)]
pub struct FileViolations {
    pub path: String,
    pub violations: Vec<Violation>,
}

/// Top-level report summarizing policy evaluation results.
#[derive(Debug, Serialize)]
pub struct PolicyReport {
    pub checked_at: String,
    pub policy_name: String,
    pub policy_description: Option<String>,
    pub total_files_checked: usize,
    pub files_with_violations: usize,
    pub total_violations: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub files: Vec<FileViolations>,
}
