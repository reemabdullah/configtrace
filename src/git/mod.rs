mod differ;
pub(crate) mod models;
mod output;
mod repo;

use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::policy;

/// Collect config change history data without outputting.
/// Used by the report module for unified audit reports.
pub fn collect_log(path_filter: Option<&str>, limit: usize) -> Result<models::GitLogReport> {
    let repository = repo::open_repo()?;
    let oids = repo::walk_commits(&repository, limit)?;
    let mut commit_results = Vec::new();

    for oid in &oids {
        let commit = repository.find_commit(*oid)?;
        let tree = commit.tree()?;

        let config_files = repo::list_config_files_in_tree(&repository, &tree, path_filter)?;

        let parent = commit.parent(0).ok();
        let parent_tree = parent.as_ref().and_then(|p| p.tree().ok());

        let parent_config_files = match &parent_tree {
            Some(pt) => repo::list_config_files_in_tree(&repository, pt, path_filter)?,
            None => Vec::new(),
        };

        let mut file_changes_list = Vec::new();

        for file_path in &config_files {
            let ext = Path::new(file_path)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            let new_content = repo::get_file_content_at_commit(&repository, &commit, file_path)?;
            let old_content = match &parent {
                Some(p) => repo::get_file_content_at_commit(&repository, p, file_path)?,
                None => None,
            };

            let new_map = new_content
                .as_ref()
                .and_then(|c| policy::parser::parse_config_content(c, ext).ok());
            let old_map = old_content
                .as_ref()
                .and_then(|c| policy::parser::parse_config_content(c, ext).ok());

            let empty = HashMap::new();
            let changes = differ::diff_config_maps(
                old_map.as_ref().unwrap_or(&empty),
                new_map.as_ref().unwrap_or(&empty),
            );

            if changes.is_empty() {
                continue;
            }

            file_changes_list.push(build_file_changes(file_path, changes, Vec::new()));
        }

        // Check for deleted files (in parent but not in current)
        for file_path in &parent_config_files {
            if config_files.contains(file_path) {
                continue;
            }
            let ext = Path::new(file_path)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            if let Some(p) = &parent
                && let Some(content) = repo::get_file_content_at_commit(&repository, p, file_path)?
                && let Ok(old_map) = policy::parser::parse_config_content(&content, ext)
            {
                let changes = differ::diff_config_maps(&old_map, &HashMap::new());
                if !changes.is_empty() {
                    file_changes_list.push(build_file_changes(file_path, changes, Vec::new()));
                }
            }
        }

        if !file_changes_list.is_empty() {
            let sig = commit.author();
            let date = chrono::DateTime::from_timestamp(sig.when().seconds(), 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();

            commit_results.push(models::CommitConfigChanges {
                commit_hash: format!("{:.7}", commit.id()),
                commit_hash_full: commit.id().to_string(),
                author: sig.name().unwrap_or("unknown").to_string(),
                date,
                message: commit.message().unwrap_or("").trim().to_string(),
                files: file_changes_list,
            });
        }
    }

    Ok(models::GitLogReport {
        repository: repository
            .workdir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        path_filter: path_filter.map(String::from),
        commits_analyzed: commit_results.len(),
        commits: commit_results,
    })
}

/// Analyze config change history across git commits.
/// Returns true if policy violations were found (for exit code 1).
pub fn git_log(
    path_filter: Option<&str>,
    limit: usize,
    format: &str,
    output_file: Option<&str>,
    policy_path: Option<&str>,
) -> Result<bool> {
    let repository = repo::open_repo()?;
    let policy_file = load_optional_policy(policy_path)?;

    let oids = repo::walk_commits(&repository, limit)?;
    let mut commit_results = Vec::new();
    let mut has_violations = false;

    for oid in &oids {
        let commit = repository.find_commit(*oid)?;
        let tree = commit.tree()?;

        let config_files = repo::list_config_files_in_tree(&repository, &tree, path_filter)?;

        // Get parent commit (if any)
        let parent = commit.parent(0).ok();
        let parent_tree = parent.as_ref().and_then(|p| p.tree().ok());

        let parent_config_files = match &parent_tree {
            Some(pt) => repo::list_config_files_in_tree(&repository, pt, path_filter)?,
            None => Vec::new(),
        };

        let mut file_changes_list = Vec::new();

        // Check files in current commit
        for file_path in &config_files {
            let ext = Path::new(file_path)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            let new_content = repo::get_file_content_at_commit(&repository, &commit, file_path)?;
            let old_content = match &parent {
                Some(p) => repo::get_file_content_at_commit(&repository, p, file_path)?,
                None => None,
            };

            let new_map = new_content
                .as_ref()
                .and_then(|c| policy::parser::parse_config_content(c, ext).ok());
            let old_map = old_content
                .as_ref()
                .and_then(|c| policy::parser::parse_config_content(c, ext).ok());

            let empty = HashMap::new();
            let changes = differ::diff_config_maps(
                old_map.as_ref().unwrap_or(&empty),
                new_map.as_ref().unwrap_or(&empty),
            );

            if changes.is_empty() {
                continue;
            }

            // Policy evaluation on the current version
            let violations = evaluate_policy_on_map(&policy_file, new_map.as_ref(), file_path);
            if !violations.is_empty() {
                has_violations = true;
            }

            file_changes_list.push(build_file_changes(file_path, changes, violations));
        }

        // Check for deleted files (in parent but not in current)
        for file_path in &parent_config_files {
            if config_files.contains(file_path) {
                continue;
            }
            let ext = Path::new(file_path)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            if let Some(p) = &parent
                && let Some(content) = repo::get_file_content_at_commit(&repository, p, file_path)?
                && let Ok(old_map) = policy::parser::parse_config_content(&content, ext)
            {
                let changes = differ::diff_config_maps(&old_map, &HashMap::new());
                if !changes.is_empty() {
                    file_changes_list.push(build_file_changes(file_path, changes, Vec::new()));
                }
            }
        }

        if !file_changes_list.is_empty() {
            let sig = commit.author();
            let date = chrono::DateTime::from_timestamp(sig.when().seconds(), 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();

            commit_results.push(models::CommitConfigChanges {
                commit_hash: format!("{:.7}", commit.id()),
                commit_hash_full: commit.id().to_string(),
                author: sig.name().unwrap_or("unknown").to_string(),
                date,
                message: commit.message().unwrap_or("").trim().to_string(),
                files: file_changes_list,
            });
        }
    }

    let report = models::GitLogReport {
        repository: repository
            .workdir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        path_filter: path_filter.map(String::from),
        commits_analyzed: commit_results.len(),
        commits: commit_results,
    };

    match format {
        "json" => output::output_log_json(&report, output_file)?,
        _ => output::output_log_terminal(&report)?,
    }

    Ok(has_violations)
}

/// Compare config files between two git refs at the key level.
/// Returns true if policy violations were found.
pub fn git_diff(
    ref1: &str,
    ref2: &str,
    path_filter: Option<&str>,
    format: &str,
    output_file: Option<&str>,
    policy_path: Option<&str>,
) -> Result<bool> {
    let repository = repo::open_repo()?;
    let policy_file = load_optional_policy(policy_path)?;

    let commit1 = repo::resolve_ref(&repository, ref1)?;
    let commit2 = repo::resolve_ref(&repository, ref2)?;

    let tree1 = commit1.tree()?;
    let tree2 = commit2.tree()?;

    let files1 = repo::list_config_files_in_tree(&repository, &tree1, path_filter)?;
    let files2 = repo::list_config_files_in_tree(&repository, &tree2, path_filter)?;

    let all_files: BTreeSet<String> = files1.into_iter().chain(files2).collect();

    let mut file_changes_list = Vec::new();
    let mut has_violations = false;
    let mut total_added = 0;
    let mut total_removed = 0;
    let mut total_changed = 0;

    for file_path in &all_files {
        let ext = Path::new(file_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let content1 = repo::get_file_content_at_commit(&repository, &commit1, file_path)?;
        let content2 = repo::get_file_content_at_commit(&repository, &commit2, file_path)?;

        let map1 = content1
            .as_ref()
            .and_then(|c| policy::parser::parse_config_content(c, ext).ok())
            .unwrap_or_default();
        let map2 = content2
            .as_ref()
            .and_then(|c| policy::parser::parse_config_content(c, ext).ok())
            .unwrap_or_default();

        let changes = differ::diff_config_maps(&map1, &map2);
        if changes.is_empty() {
            continue;
        }

        // Policy evaluation on the target ref (ref2)
        let violations = evaluate_policy_on_map(&policy_file, Some(&map2), file_path);
        if !violations.is_empty() {
            has_violations = true;
        }

        let fc = build_file_changes(file_path, changes, violations);
        total_added += fc.keys_added;
        total_removed += fc.keys_removed;
        total_changed += fc.keys_changed;
        file_changes_list.push(fc);
    }

    let report = models::GitDiffReport {
        repository: repository
            .workdir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        ref_from: ref1.to_string(),
        ref_to: ref2.to_string(),
        path_filter: path_filter.map(String::from),
        total_files_changed: file_changes_list.len(),
        total_keys_added: total_added,
        total_keys_removed: total_removed,
        total_keys_changed: total_changed,
        files: file_changes_list,
    };

    match format {
        "json" => output::output_diff_json(&report, output_file)?,
        _ => output::output_diff_terminal(&report)?,
    }

    Ok(has_violations)
}

// ===== Helpers =====

fn load_optional_policy(
    policy_path: Option<&str>,
) -> Result<Option<crate::policy::models::PolicyFile>> {
    match policy_path {
        Some(p) => {
            let pf = policy::loader::load_policy(Path::new(p))
                .with_context(|| format!("Failed to load policy: {}", p))?;
            Ok(Some(pf))
        }
        None => Ok(None),
    }
}

fn evaluate_policy_on_map(
    policy_file: &Option<crate::policy::models::PolicyFile>,
    config_map: Option<&HashMap<String, String>>,
    file_path: &str,
) -> Vec<crate::policy::models::Violation> {
    let Some(pf) = policy_file else {
        return Vec::new();
    };
    let Some(map) = config_map else {
        return Vec::new();
    };

    let mut violations = Vec::new();
    for rule in &pf.rules {
        if !policy::evaluator::rule_applies_to_file(rule, Path::new(file_path)) {
            continue;
        }
        if let Some(v) = policy::evaluator::evaluate_rule(rule, Path::new(file_path), map) {
            violations.push(v);
        }
    }
    violations
}

fn build_file_changes(
    path: &str,
    changes: Vec<models::KeyChange>,
    violations: Vec<crate::policy::models::Violation>,
) -> models::FileChanges {
    let keys_added = changes
        .iter()
        .filter(|c| c.kind == models::KeyChangeKind::Added)
        .count();
    let keys_removed = changes
        .iter()
        .filter(|c| c.kind == models::KeyChangeKind::Removed)
        .count();
    let keys_changed = changes
        .iter()
        .filter(|c| c.kind == models::KeyChangeKind::Changed)
        .count();

    models::FileChanges {
        path: path.to_string(),
        keys_added,
        keys_removed,
        keys_changed,
        changes,
        violations,
    }
}
