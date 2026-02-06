use std::collections::{BTreeSet, HashMap};

use super::models::{KeyChange, KeyChangeKind};

/// Compare two flattened config maps and produce key-level changes.
/// Uses BTreeSet for deterministic key ordering in output.
pub fn diff_config_maps(
    old: &HashMap<String, String>,
    new: &HashMap<String, String>,
) -> Vec<KeyChange> {
    let mut changes = Vec::new();
    let all_keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();

    for key in all_keys {
        match (old.get(key), new.get(key)) {
            (None, Some(new_val)) => {
                changes.push(KeyChange {
                    key: key.clone(),
                    kind: KeyChangeKind::Added,
                    old_value: None,
                    new_value: Some(new_val.clone()),
                });
            }
            (Some(old_val), None) => {
                changes.push(KeyChange {
                    key: key.clone(),
                    kind: KeyChangeKind::Removed,
                    old_value: Some(old_val.clone()),
                    new_value: None,
                });
            }
            (Some(old_val), Some(new_val)) if old_val != new_val => {
                changes.push(KeyChange {
                    key: key.clone(),
                    kind: KeyChangeKind::Changed,
                    old_value: Some(old_val.clone()),
                    new_value: Some(new_val.clone()),
                });
            }
            _ => {}
        }
    }

    changes
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

    #[test]
    fn test_empty_maps() {
        let old = HashMap::new();
        let new = HashMap::new();
        assert!(diff_config_maps(&old, &new).is_empty());
    }

    #[test]
    fn test_identical_maps() {
        let map = make_map(&[("a", "1"), ("b", "2")]);
        assert!(diff_config_maps(&map, &map).is_empty());
    }

    #[test]
    fn test_added_keys() {
        let old = HashMap::new();
        let new = make_map(&[("database.host", "localhost")]);
        let changes = diff_config_maps(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, KeyChangeKind::Added);
        assert_eq!(changes[0].key, "database.host");
        assert_eq!(changes[0].new_value.as_deref(), Some("localhost"));
        assert!(changes[0].old_value.is_none());
    }

    #[test]
    fn test_removed_keys() {
        let old = make_map(&[("debug", "true")]);
        let new = HashMap::new();
        let changes = diff_config_maps(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, KeyChangeKind::Removed);
        assert_eq!(changes[0].key, "debug");
        assert_eq!(changes[0].old_value.as_deref(), Some("true"));
        assert!(changes[0].new_value.is_none());
    }

    #[test]
    fn test_changed_keys() {
        let old = make_map(&[("database.host", "localhost")]);
        let new = make_map(&[("database.host", "db.prod.internal")]);
        let changes = diff_config_maps(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, KeyChangeKind::Changed);
        assert_eq!(changes[0].old_value.as_deref(), Some("localhost"));
        assert_eq!(changes[0].new_value.as_deref(), Some("db.prod.internal"));
    }

    #[test]
    fn test_mixed_changes() {
        let old = make_map(&[("a", "1"), ("b", "2"), ("c", "3")]);
        let new = make_map(&[("a", "1"), ("b", "changed"), ("d", "4")]);
        let changes = diff_config_maps(&old, &new);

        assert_eq!(changes.len(), 3);

        let changed: Vec<_> = changes
            .iter()
            .filter(|c| c.kind == KeyChangeKind::Changed)
            .collect();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].key, "b");

        let removed: Vec<_> = changes
            .iter()
            .filter(|c| c.kind == KeyChangeKind::Removed)
            .collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].key, "c");

        let added: Vec<_> = changes
            .iter()
            .filter(|c| c.kind == KeyChangeKind::Added)
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].key, "d");
    }

    #[test]
    fn test_deterministic_ordering() {
        let old = make_map(&[("z", "1"), ("a", "2")]);
        let new = make_map(&[("z", "changed"), ("a", "changed")]);
        let changes = diff_config_maps(&old, &new);
        assert_eq!(changes[0].key, "a");
        assert_eq!(changes[1].key, "z");
    }
}
