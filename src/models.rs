use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub created_at: String,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    PrivateKey,
    GithubToken,
    JwtToken,
    DatabaseUrl,
    GenericPassword,
    GenericApiKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretFinding {
    pub secret_type: SecretType,
    pub severity: Severity,
    pub line: usize,
    pub snippet: String,
    pub matched_pattern: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileSecrets {
    pub path: String,
    pub findings: Vec<SecretFinding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretReport {
    pub scanned_at: String,
    pub total_files: usize,
    pub files_with_secrets: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub files: Vec<FileSecrets>,
}
