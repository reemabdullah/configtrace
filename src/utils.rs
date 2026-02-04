use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// Compute SHA-256 hash of a file
pub fn hash_file(p: &Path) -> Result<String> {
    let data = fs::read(p)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Check if a file is a supported config format
pub fn is_config(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|s| s.to_str()),
        Some("yml" | "yaml" | "json" | "toml")
    )
}
