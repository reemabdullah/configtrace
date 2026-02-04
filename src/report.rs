use anyhow::Result;
use std::fs;

use crate::models::Snapshot;

/// Generate a Markdown report from a snapshot
pub fn report(snapshot: &str, out: &str) -> Result<()> {
    let snap: Snapshot = serde_json::from_slice(&fs::read(snapshot)?)?;
    let mut md = String::new();
    md.push_str(&format!(
        "# ConfigTrace Report\n\nGenerated: {}\n\n",
        snap.created_at
    ));
    md.push_str("| File | SHA256 |\n|---|---|\n");
    for e in snap.entries {
        md.push_str(&format!("| {} | `{}` |\n", e.path, e.hash));
    }
    fs::write(out, md)?;
    println!("Wrote report to {out}");
    Ok(())
}
