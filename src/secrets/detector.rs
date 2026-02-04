use anyhow::Result;
use chrono::Utc;
use std::fs;
use walkdir::WalkDir;

use crate::models::{FileSecrets, SecretFinding, SecretReport};
use crate::utils::is_config;

use super::patterns::SECRET_PATTERNS;

/// Check if a line should be skipped (false positive filtering)
fn should_skip_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.contains("example.com")
        || trimmed.contains("localhost")
        || trimmed.contains("127.0.0.1")
        || trimmed.contains("REPLACE_ME")
        || trimmed.contains("YOUR_KEY_HERE")
        || trimmed.contains("XXX")
        || trimmed.contains("${")
        || trimmed.contains("{{")
        || trimmed.contains("%")
}

/// Redact a secret, showing only first 4 characters
fn redact_secret(text: &str, start: usize, end: usize) -> String {
    let secret = &text[start..end];
    if secret.len() <= 4 {
        return "...".to_string();
    }
    format!("{}...", &secret[..4.min(secret.len())])
}

/// Detect secrets in a single file
pub fn detect_secrets_in_file(path: &std::path::Path) -> Result<Vec<SecretFinding>> {
    let content = fs::read_to_string(path)?;
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        if should_skip_line(line) {
            continue;
        }

        for pattern in SECRET_PATTERNS.iter() {
            if let Some(captures) = pattern.regex.captures(line) {
                let full_match = captures.get(0).unwrap();
                let redacted = redact_secret(line, full_match.start(), full_match.end());

                // Create context snippet (show some characters before and after)
                let snippet_start = full_match.start().saturating_sub(10);
                let snippet_end = (full_match.end() + 10).min(line.len());
                let before = &line[snippet_start..full_match.start()];
                let after = &line[full_match.end()..snippet_end];
                let snippet = format!("{}{}{}", before, redacted, after);

                findings.push(SecretFinding {
                    secret_type: pattern.secret_type.clone(),
                    severity: pattern.severity.clone(),
                    line: line_num + 1,
                    snippet,
                    matched_pattern: pattern.name.to_string(),
                });
            }
        }
    }

    Ok(findings)
}

/// Scan a directory recursively for secrets in config files
pub fn scan_directory(path: &str) -> Result<SecretReport> {
    let mut files_with_secrets = Vec::new();
    let mut total_files = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() && is_config(p) {
            total_files += 1;

            match detect_secrets_in_file(p) {
                Ok(findings) if !findings.is_empty() => {
                    // Count by severity
                    for finding in &findings {
                        match finding.severity {
                            crate::models::Severity::Critical => critical_count += 1,
                            crate::models::Severity::High => high_count += 1,
                        }
                    }

                    files_with_secrets.push(FileSecrets {
                        path: p.display().to_string(),
                        findings,
                    });
                }
                Ok(_) => {} // No findings, skip
                Err(e) => {
                    eprintln!("Warning: Could not scan {}: {}", p.display(), e);
                }
            }
        }
    }

    let total_findings = critical_count + high_count;

    Ok(SecretReport {
        scanned_at: Utc::now().to_rfc3339(),
        total_files,
        files_with_secrets: files_with_secrets.len(),
        total_findings,
        critical_count,
        high_count,
        files: files_with_secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_skip_line() {
        assert!(should_skip_line(""));
        assert!(should_skip_line("   "));
        assert!(should_skip_line("# This is a comment"));
        assert!(should_skip_line("// This is a comment"));
        assert!(should_skip_line("password: example.com"));
        assert!(should_skip_line("api_key: REPLACE_ME"));
        assert!(should_skip_line("token: ${TOKEN}"));
        assert!(should_skip_line("secret: {{SECRET}}"));
        assert!(!should_skip_line("password: realpassword123"));
    }

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("secretkey123456", 0, 15), "secr...");
        assert_eq!(redact_secret("abc", 0, 3), "...");
    }
}
