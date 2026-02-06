use anyhow::{Context, Result};
use git2::{Commit, ObjectType, Repository, Sort, Tree};
use std::path::Path;

use crate::utils::is_config;

/// Open the git repository at or above the current directory.
pub fn open_repo() -> Result<Repository> {
    Repository::discover(".").context("Not a git repository (or any parent directory)")
}

/// Resolve a ref string (branch, tag, commit hash) to a Commit.
pub fn resolve_ref<'a>(repo: &'a Repository, refspec: &str) -> Result<Commit<'a>> {
    let obj = repo
        .revparse_single(refspec)
        .with_context(|| format!("Failed to resolve git ref: {}", refspec))?;
    obj.peel_to_commit()
        .with_context(|| format!("'{}' does not point to a commit", refspec))
}

/// Get the content of a file at a specific commit.
/// Returns None if the file does not exist at that commit.
pub fn get_file_content_at_commit(
    repo: &Repository,
    commit: &Commit,
    file_path: &str,
) -> Result<Option<String>> {
    let tree = commit.tree()?;
    match tree.get_path(Path::new(file_path)) {
        Ok(entry) => {
            let blob = repo
                .find_blob(entry.id())
                .with_context(|| format!("Failed to read blob for {}", file_path))?;
            match std::str::from_utf8(blob.content()) {
                Ok(content) => Ok(Some(content.to_string())),
                Err(_) => Ok(None), // Binary file, skip
            }
        }
        Err(_) => Ok(None),
    }
}

/// List all config files (yaml/json/toml) in a tree, optionally filtered by path prefix.
pub fn list_config_files_in_tree(
    repo: &Repository,
    tree: &Tree,
    path_filter: Option<&str>,
) -> Result<Vec<String>> {
    let mut files = Vec::new();

    // If a path filter is specified, try to narrow the tree walk
    if let Some(filter) = path_filter {
        // Try to get the subtree at the filter path
        if let Ok(entry) = tree.get_path(Path::new(filter)) {
            if let Ok(subtree) = repo.find_tree(entry.id()) {
                collect_config_files(repo, &subtree, filter, &mut files)?;
            } else {
                // It's a file, not a directory - check if it's a config file
                let full_path = filter.to_string();
                if is_config(Path::new(&full_path)) {
                    files.push(full_path);
                }
            }
        }
    } else {
        collect_config_files(repo, tree, "", &mut files)?;
    }

    files.sort();
    Ok(files)
}

fn collect_config_files(
    _repo: &Repository,
    tree: &Tree,
    prefix: &str,
    files: &mut Vec<String>,
) -> Result<()> {
    tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            let full_path = if prefix.is_empty() {
                if dir.is_empty() {
                    entry.name().unwrap_or("").to_string()
                } else {
                    format!("{}{}", dir, entry.name().unwrap_or(""))
                }
            } else {
                let inner = if dir.is_empty() {
                    entry.name().unwrap_or("").to_string()
                } else {
                    format!("{}{}", dir, entry.name().unwrap_or(""))
                };
                if prefix.ends_with('/') {
                    format!("{}{}", prefix, inner)
                } else {
                    format!("{}/{}", prefix, inner)
                }
            };

            if is_config(Path::new(&full_path)) {
                files.push(full_path);
            }
        }
        git2::TreeWalkResult::Ok
    })?;
    Ok(())
}

/// Walk commits starting from HEAD, limited to N commits.
pub fn walk_commits(repo: &Repository, limit: usize) -> Result<Vec<git2::Oid>> {
    let mut revwalk = repo.revwalk()?;
    revwalk
        .push_head()
        .context("Failed to start revision walk from HEAD")?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut oids = Vec::new();
    for oid_result in revwalk {
        if oids.len() >= limit {
            break;
        }
        oids.push(oid_result?);
    }
    Ok(oids)
}
