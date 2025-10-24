use std::{fs, path::Path};
use anyhow::Result;
use clap::{Parser, Subcommand};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use chrono::Utc;
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(name="configtrace", about="Track & audit configuration changes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory and produce a snapshot (hashes of YAML/JSON/TOML)
    Scan { path: String, #[arg(long, default_value="snapshot.json")] out: String },
    /// Compare two snapshots and print a simple diff
    Diff { old: String, new: String },
    /// Generate a Markdown report from a snapshot
    Report { snapshot: String, #[arg(long, default_value="report.md")] out: String },
}

#[derive(Serialize, Deserialize)]
struct Entry { path: String, hash: String }
#[derive(Serialize, Deserialize)]
struct Snapshot { created_at: String, entries: Vec<Entry> }

fn hash_file(p: &Path) -> Result<String> {
    let data = fs::read(p)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_config(p: &Path) -> bool {
    matches!(p.extension().and_then(|s| s.to_str()),
        Some("yml" | "yaml" | "json" | "toml"))
}

fn scan(path: &str, out: &str) -> Result<()> {
    let mut entries = Vec::new();
    for e in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_file() && is_config(p) {
            let h = hash_file(p)?;
            entries.push(Entry { path: p.display().to_string(), hash: h });
        }
    }
    let snapshot = Snapshot { created_at: Utc::now().to_rfc3339(), entries };
    fs::write(out, serde_json::to_vec_pretty(&snapshot)?)?;
    println!("Wrote snapshot to {out}");
    Ok(())
}

fn diff(old: &str, new: &str) -> Result<()> {
    let o: Snapshot = serde_json::from_slice(&fs::read(old)?)?;
    let n: Snapshot = serde_json::from_slice(&fs::read(new)?)?;

    use std::collections::HashMap;
    let map_old: HashMap<_, _> = o.entries.iter().map(|e| (&e.path, &e.hash)).collect();
    let map_new: HashMap<_, _> = n.entries.iter().map(|e| (&e.path, &e.hash)).collect();

    for (path, h_new) in &map_new {
        match map_old.get(path) {
            None => println!("ADDED   {path}"),
            Some(h_old) if *h_old != *h_new => println!("CHANGED {path}"),
            _ => {}
        }
    }
    for (path, _) in &map_old {
        if !map_new.contains_key(path) {
            println!("REMOVED {path}");
        }
    }
    Ok(())
}

fn report(snapshot: &str, out: &str) -> Result<()> {
    let snap: Snapshot = serde_json::from_slice(&fs::read(snapshot)?)?;
    let mut md = String::new();
    md.push_str(&format!("# ConfigTrace Report\n\nGenerated: {}\n\n", snap.created_at));
    md.push_str("| File | SHA256 |\n|---|---|\n");
    for e in snap.entries {
        md.push_str(&format!("| {} | `{}` |\n", e.path, e.hash));
    }
    fs::write(out, md)?;
    println!("Wrote report to {out}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, out } => scan(&path, &out)?,
        Commands::Diff { old, new } => diff(&old, &new)?,
        Commands::Report { snapshot, out } => report(&snapshot, &out)?,
    }
    Ok(())
}
