use lazy_static::lazy_static;
use regex::Regex;

use crate::models::{SecretType, Severity};

pub struct SecretPattern {
    pub name: &'static str,
    pub regex: Regex,
    pub secret_type: SecretType,
    pub severity: Severity,
}

lazy_static! {
    pub static ref SECRET_PATTERNS: Vec<SecretPattern> = vec![
        // AWS Access Key ID
        SecretPattern {
            name: "AWS Access Key ID",
            regex: Regex::new(r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
            secret_type: SecretType::AwsAccessKey,
            severity: Severity::Critical,
        },
        // AWS Secret Access Key
        SecretPattern {
            name: "AWS Secret Access Key",
            regex: Regex::new(r"(?i)aws[_-]?secret[_-]?access[_-]?key['\x22]?\s*[:=]\s*['\x22]?([A-Za-z0-9/+=]{40})['\x22]?").unwrap(),
            secret_type: SecretType::AwsSecretKey,
            severity: Severity::Critical,
        },
        // GCP Service Account JSON
        SecretPattern {
            name: "GCP Service Account Key",
            regex: Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
            secret_type: SecretType::GcpServiceAccount,
            severity: Severity::Critical,
        },
        // RSA/EC/OpenSSH Private Key
        SecretPattern {
            name: "RSA/EC Private Key",
            regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            secret_type: SecretType::PrivateKey,
            severity: Severity::Critical,
        },
        // GitHub Personal Access Token
        SecretPattern {
            name: "GitHub Token",
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,255}").unwrap(),
            secret_type: SecretType::GithubToken,
            severity: Severity::Critical,
        },
        // Database Connection String
        SecretPattern {
            name: "Database Connection String",
            regex: Regex::new(r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@").unwrap(),
            secret_type: SecretType::DatabaseUrl,
            severity: Severity::Critical,
        },
        // Generic Password
        SecretPattern {
            name: "Generic Password",
            regex: Regex::new(r"(?i)(password|passwd|pwd)['\x22]?\s*[:=]\s*['\x22]?([^'\x22>\s]{8,})['\x22]?").unwrap(),
            secret_type: SecretType::GenericPassword,
            severity: Severity::Critical,
        },
        // Generic API Key
        SecretPattern {
            name: "Generic API Key",
            regex: Regex::new(r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\x22]?\s*[:=]\s*['\x22]?([A-Za-z0-9_-]{20,})['\x22]?").unwrap(),
            secret_type: SecretType::GenericApiKey,
            severity: Severity::High,
        },
        // JWT Token
        SecretPattern {
            name: "JWT Token",
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(),
            secret_type: SecretType::JwtToken,
            severity: Severity::High,
        },
    ];
}
