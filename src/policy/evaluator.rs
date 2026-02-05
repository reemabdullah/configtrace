use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

use crate::utils::is_config;

use super::models::*;
use super::parser::parse_config_file;

/// Evaluate all rules in a policy against all config files under the given path.
pub fn evaluate_policy(path: &str, policy: &PolicyFile) -> Result<PolicyReport> {
    let mut all_file_violations = Vec::new();
    let mut total_files = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if !file_path.is_file() || !is_config(file_path) {
            continue;
        }
        total_files += 1;

        let flat_map = match parse_config_file(file_path) {
            Ok(map) => map,
            Err(e) => {
                eprintln!("Warning: Could not parse {}: {}", file_path.display(), e);
                continue;
            }
        };

        let mut violations = Vec::new();

        for rule in &policy.rules {
            if !rule_applies_to_file(rule, file_path) {
                continue;
            }

            if let Some(violation) = evaluate_rule(rule, file_path, &flat_map) {
                match violation.severity {
                    PolicySeverity::Critical => critical_count += 1,
                    PolicySeverity::High => high_count += 1,
                    PolicySeverity::Medium => medium_count += 1,
                    PolicySeverity::Low => low_count += 1,
                }
                violations.push(violation);
            }
        }

        if !violations.is_empty() {
            all_file_violations.push(FileViolations {
                path: file_path.display().to_string(),
                violations,
            });
        }
    }

    let total_violations = critical_count + high_count + medium_count + low_count;

    Ok(PolicyReport {
        checked_at: Utc::now().to_rfc3339(),
        policy_name: policy.name.clone(),
        policy_description: policy.description.clone(),
        total_files_checked: total_files,
        files_with_violations: all_file_violations.len(),
        total_violations,
        critical_count,
        high_count,
        medium_count,
        low_count,
        files: all_file_violations,
    })
}

/// Check if a rule's glob pattern matches the given file path.
fn rule_applies_to_file(rule: &RuleDefinition, file_path: &Path) -> bool {
    match &rule.pattern {
        None => true,
        Some(pat) => {
            let glob_pattern = glob::Pattern::new(pat).unwrap(); // Pre-validated in loader
            if pat.contains('/') || pat.contains("**") {
                glob_pattern.matches_path(file_path)
            } else {
                file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| glob_pattern.matches(n))
                    .unwrap_or(false)
            }
        }
    }
}

/// Evaluate a single rule against a flattened config map.
/// Returns Some(Violation) if the rule is violated, None if compliant.
fn evaluate_rule(
    rule: &RuleDefinition,
    file_path: &Path,
    flat_map: &HashMap<String, String>,
) -> Option<Violation> {
    let file_str = file_path.display().to_string();

    match &rule.check {
        CheckDefinition::RequiredKey { key } => {
            let key_exists = flat_map.contains_key(key)
                || flat_map.keys().any(|k| k.starts_with(&format!("{}.", key)));

            if !key_exists {
                return Some(Violation {
                    rule_id: rule.id.clone(),
                    rule_description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    file: file_str,
                    key: key.clone(),
                    message: format!("Required key '{}' is missing", key),
                });
            }
        }

        CheckDefinition::ForbiddenKey { key } => {
            let key_exists = flat_map.contains_key(key)
                || flat_map.keys().any(|k| k.starts_with(&format!("{}.", key)));

            if key_exists {
                return Some(Violation {
                    rule_id: rule.id.clone(),
                    rule_description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    file: file_str,
                    key: key.clone(),
                    message: format!("Forbidden key '{}' is present", key),
                });
            }
        }

        CheckDefinition::ValueMatch { key, regex } => {
            if let Some(value) = flat_map.get(key) {
                let re = regex::Regex::new(regex).unwrap(); // Pre-validated
                if !re.is_match(value) {
                    return Some(Violation {
                        rule_id: rule.id.clone(),
                        rule_description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        file: file_str,
                        key: key.clone(),
                        message: format!(
                            "Value '{}' for key '{}' does not match pattern '{}'",
                            value, key, regex
                        ),
                    });
                }
            }
        }

        CheckDefinition::ValueEnum { key, values } => {
            if let Some(value) = flat_map.get(key)
                && !values.contains(value)
            {
                return Some(Violation {
                    rule_id: rule.id.clone(),
                    rule_description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    file: file_str,
                    key: key.clone(),
                    message: format!(
                        "Value '{}' for key '{}' is not in allowed set: [{}]",
                        value,
                        key,
                        values.join(", ")
                    ),
                });
            }
        }

        CheckDefinition::ForbiddenValue { key, value } => {
            if let Some(actual) = flat_map.get(key)
                && actual == value
            {
                return Some(Violation {
                    rule_id: rule.id.clone(),
                    rule_description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    file: file_str,
                    key: key.clone(),
                    message: format!("Forbidden value '{}' found for key '{}'", value, key),
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn make_rule(id: &str, severity: PolicySeverity, check: CheckDefinition) -> RuleDefinition {
        RuleDefinition {
            id: id.to_string(),
            description: Some(id.to_string()),
            severity,
            pattern: None,
            check,
        }
    }

    #[test]
    fn test_required_key_present() {
        let map = make_map(&[("logging.level", "info")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::RequiredKey {
                key: "logging.level".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_required_key_present_as_parent() {
        let map = make_map(&[("logging.level", "info"), ("logging.format", "json")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::RequiredKey {
                key: "logging".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_required_key_missing() {
        let map = make_map(&[("app.name", "test")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::RequiredKey {
                key: "logging.level".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("missing"));
    }

    #[test]
    fn test_forbidden_key_absent() {
        let map = make_map(&[("app.name", "test")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Critical,
            CheckDefinition::ForbiddenKey {
                key: "debug".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_forbidden_key_present() {
        let map = make_map(&[("debug", "true")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Critical,
            CheckDefinition::ForbiddenKey {
                key: "debug".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("present"));
    }

    #[test]
    fn test_value_match_passes() {
        let map = make_map(&[("aws.region", "us-east-1")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::ValueMatch {
                key: "aws.region".to_string(),
                regex: "^us-".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_value_match_fails() {
        let map = make_map(&[("aws.region", "eu-west-1")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::ValueMatch {
                key: "aws.region".to_string(),
                regex: "^us-".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("does not match"));
    }

    #[test]
    fn test_value_match_missing_key_no_violation() {
        let map = make_map(&[("app.name", "test")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::High,
            CheckDefinition::ValueMatch {
                key: "aws.region".to_string(),
                regex: "^us-".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_value_enum_valid() {
        let map = make_map(&[("logging.level", "info")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Medium,
            CheckDefinition::ValueEnum {
                key: "logging.level".to_string(),
                values: vec!["debug".into(), "info".into(), "warn".into(), "error".into()],
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_value_enum_invalid() {
        let map = make_map(&[("logging.level", "trace")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Medium,
            CheckDefinition::ValueEnum {
                key: "logging.level".to_string(),
                values: vec!["debug".into(), "info".into(), "warn".into(), "error".into()],
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("not in allowed set"));
    }

    #[test]
    fn test_forbidden_value_different() {
        let map = make_map(&[("debug", "false")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Critical,
            CheckDefinition::ForbiddenValue {
                key: "debug".to_string(),
                value: "true".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_none());
    }

    #[test]
    fn test_forbidden_value_matches() {
        let map = make_map(&[("debug", "true")]);
        let rule = make_rule(
            "r1",
            PolicySeverity::Critical,
            CheckDefinition::ForbiddenValue {
                key: "debug".to_string(),
                value: "true".to_string(),
            },
        );
        let result = evaluate_rule(&rule, Path::new("test.yaml"), &map);
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("Forbidden value"));
    }

    #[test]
    fn test_rule_applies_no_pattern() {
        let rule = make_rule(
            "r1",
            PolicySeverity::Low,
            CheckDefinition::RequiredKey {
                key: "x".to_string(),
            },
        );
        assert!(rule_applies_to_file(&rule, Path::new("anything.yaml")));
    }

    #[test]
    fn test_rule_applies_glob_match() {
        let mut rule = make_rule(
            "r1",
            PolicySeverity::Low,
            CheckDefinition::RequiredKey {
                key: "x".to_string(),
            },
        );
        rule.pattern = Some("*.yaml".to_string());
        assert!(rule_applies_to_file(&rule, Path::new("config.yaml")));
        assert!(!rule_applies_to_file(&rule, Path::new("config.json")));
    }
}
