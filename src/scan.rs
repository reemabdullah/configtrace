use anyhow::Result;
use chrono::Utc;
use std::fs;
use walkdir::WalkDir;

use crate::models::{Entry, Snapshot};
use crate::utils::{hash_file, is_config};

/// Scan a directory recursively and create a snapshot of config files
pub fn scan(path: &str, out: &str) -> Result<()> {
    let mut entries = Vec::new();
    for e in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_file() && is_config(p) {
            let h = hash_file(p)?;
            entries.push(Entry {
                path: p.display().to_string(),
                hash: h,
            });
        }
    }
    let snapshot = Snapshot {
        created_at: Utc::now().to_rfc3339(),
        entries,
    };
    fs::write(out, serde_json::to_vec_pretty(&snapshot)?)?;
    println!("Wrote snapshot to {out}");
    Ok(())
}
