use serde::Serialize;

use crate::policy::models::Violation;

/// How a config key changed between two states.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyChangeKind {
    Added,
    Removed,
    Changed,
}

/// A single key-level change within a config file.
#[derive(Debug, Clone, Serialize)]
pub struct KeyChange {
    pub key: String,
    pub kind: KeyChangeKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Changes to a single config file between two states.
#[derive(Debug, Clone, Serialize)]
pub struct FileChanges {
    pub path: String,
    pub keys_added: usize,
    pub keys_removed: usize,
    pub keys_changed: usize,
    pub changes: Vec<KeyChange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<Violation>,
}

/// A commit's config changes for the `git log` subcommand.
#[derive(Debug, Clone, Serialize)]
pub struct CommitConfigChanges {
    pub commit_hash: String,
    pub commit_hash_full: String,
    pub author: String,
    pub date: String,
    pub message: String,
    pub files: Vec<FileChanges>,
}

/// Top-level report for `configtrace git log`.
#[derive(Debug, Serialize)]
pub struct GitLogReport {
    pub repository: String,
    pub path_filter: Option<String>,
    pub commits_analyzed: usize,
    pub commits: Vec<CommitConfigChanges>,
}

/// Top-level report for `configtrace git diff`.
#[derive(Debug, Serialize)]
pub struct GitDiffReport {
    pub repository: String,
    pub ref_from: String,
    pub ref_to: String,
    pub path_filter: Option<String>,
    pub total_files_changed: usize,
    pub total_keys_added: usize,
    pub total_keys_removed: usize,
    pub total_keys_changed: usize,
    pub files: Vec<FileChanges>,
}
