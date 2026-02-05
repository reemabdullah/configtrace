use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Parse a config file (YAML/JSON/TOML) into a flat key-value map.
/// Nested keys are joined with dots: `database.host = "localhost"`
pub fn parse_config_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    let value: serde_json::Value = match ext {
        "yaml" | "yml" => {
            let yaml_val: serde_yaml::Value = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;
            serde_json::to_value(yaml_val)?
        }
        "json" => serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse JSON: {}", path.display()))?,
        "toml" => {
            let toml_val: toml::Value = toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML: {}", path.display()))?;
            serde_json::to_value(toml_val)?
        }
        _ => anyhow::bail!("Unsupported config format: {}", ext),
    };

    let mut map = HashMap::new();
    flatten("", &value, &mut map);
    Ok(map)
}

/// Recursively flatten a serde_json::Value into dot-notation keys.
fn flatten(prefix: &str, value: &serde_json::Value, map: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Object(obj) => {
            for (k, v) in obj {
                let new_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten(&new_key, v, map);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let new_key = format!("{}[{}]", prefix, i);
                flatten(&new_key, v, map);
            }
        }
        serde_json::Value::String(s) => {
            map.insert(prefix.to_string(), s.clone());
        }
        serde_json::Value::Number(n) => {
            map.insert(prefix.to_string(), n.to_string());
        }
        serde_json::Value::Bool(b) => {
            map.insert(prefix.to_string(), b.to_string());
        }
        serde_json::Value::Null => {
            map.insert(prefix.to_string(), "null".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str, extension: &str) -> NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(&format!(".{}", extension))
            .tempfile()
            .unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_flatten_yaml() {
        let file = write_temp_file(
            "database:\n  host: localhost\n  port: 5432\n",
            "yaml",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("database.host").unwrap(), "localhost");
        assert_eq!(map.get("database.port").unwrap(), "5432");
    }

    #[test]
    fn test_flatten_json() {
        let file = write_temp_file(
            r#"{"app": {"name": "test", "debug": true}}"#,
            "json",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("app.name").unwrap(), "test");
        assert_eq!(map.get("app.debug").unwrap(), "true");
    }

    #[test]
    fn test_flatten_toml() {
        let file = write_temp_file(
            "[server]\nname = \"prod\"\nport = 8080\n",
            "toml",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("server.name").unwrap(), "prod");
        assert_eq!(map.get("server.port").unwrap(), "8080");
    }

    #[test]
    fn test_flatten_deeply_nested() {
        let file = write_temp_file(
            r#"{"a": {"b": {"c": {"d": "deep"}}}}"#,
            "json",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("a.b.c.d").unwrap(), "deep");
    }

    #[test]
    fn test_flatten_array() {
        let file = write_temp_file(
            r#"{"servers": [{"host": "a"}, {"host": "b"}]}"#,
            "json",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("servers[0].host").unwrap(), "a");
        assert_eq!(map.get("servers[1].host").unwrap(), "b");
    }

    #[test]
    fn test_flatten_boolean_and_null() {
        let file = write_temp_file(
            r#"{"enabled": true, "disabled": false, "value": null}"#,
            "json",
        );
        let map = parse_config_file(file.path()).unwrap();
        assert_eq!(map.get("enabled").unwrap(), "true");
        assert_eq!(map.get("disabled").unwrap(), "false");
        assert_eq!(map.get("value").unwrap(), "null");
    }
}
