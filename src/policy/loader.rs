use anyhow::{Context, Result, ensure};
use std::collections::HashSet;
use std::path::Path;

use super::models::{CheckDefinition, PolicyFile};

/// Load and validate a policy file from disk.
pub fn load_policy(path: &Path) -> Result<PolicyFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read policy file: {}", path.display()))?;

    let policy: PolicyFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse policy file: {}", path.display()))?;

    validate_policy(&policy)?;
    Ok(policy)
}

/// Validate that the policy is well-formed.
fn validate_policy(policy: &PolicyFile) -> Result<()> {
    ensure!(
        !policy.rules.is_empty(),
        "Policy must contain at least one rule"
    );

    let mut seen_ids = HashSet::new();
    for rule in &policy.rules {
        ensure!(
            seen_ids.insert(&rule.id),
            "Duplicate rule id: '{}'",
            rule.id
        );

        // Validate regex compiles for value_match rules
        if let CheckDefinition::ValueMatch { regex, .. } = &rule.check {
            regex::Regex::new(regex)
                .with_context(|| format!("Invalid regex in rule '{}': {}", rule.id, regex))?;
        }

        // Validate glob pattern if present
        if let Some(pattern) = &rule.pattern {
            glob::Pattern::new(pattern).with_context(|| {
                format!("Invalid glob pattern in rule '{}': {}", rule.id, pattern)
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_policy_file(content: &str) -> NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_load_valid_policy() {
        let file = write_policy_file(
            r#"
name: "test-policy"
description: "A test policy"
rules:
  - id: check-debug
    description: "No debug mode"
    severity: critical
    check:
      type: forbidden_value
      key: "debug"
      value: "true"
"#,
        );
        let policy = load_policy(file.path()).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_load_policy_empty_rules() {
        let file = write_policy_file(
            r#"
name: "empty"
rules: []
"#,
        );
        let result = load_policy(file.path());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("at least one rule")
        );
    }

    #[test]
    fn test_load_policy_duplicate_ids() {
        let file = write_policy_file(
            r#"
name: "dupes"
rules:
  - id: same-id
    check:
      type: required_key
      key: "a"
  - id: same-id
    check:
      type: required_key
      key: "b"
"#,
        );
        let result = load_policy(file.path());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Duplicate rule id")
        );
    }

    #[test]
    fn test_load_policy_invalid_regex() {
        let file = write_policy_file(
            r#"
name: "bad-regex"
rules:
  - id: bad
    check:
      type: value_match
      key: "x"
      regex: "[invalid"
"#,
        );
        let result = load_policy(file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid regex"));
    }

    #[test]
    fn test_load_policy_default_severity() {
        let file = write_policy_file(
            r#"
name: "defaults"
rules:
  - id: no-severity
    check:
      type: required_key
      key: "something"
"#,
        );
        let policy = load_policy(file.path()).unwrap();
        assert_eq!(
            policy.rules[0].severity,
            super::super::models::PolicySeverity::Medium
        );
    }
}
