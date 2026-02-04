use anyhow::Result;
use std::collections::HashMap;
use std::fs;

use crate::models::Snapshot;

/// Compare two snapshots and print differences
pub fn diff(old: &str, new: &str) -> Result<()> {
    let o: Snapshot = serde_json::from_slice(&fs::read(old)?)?;
    let n: Snapshot = serde_json::from_slice(&fs::read(new)?)?;

    let map_old: HashMap<_, _> = o.entries.iter().map(|e| (&e.path, &e.hash)).collect();
    let map_new: HashMap<_, _> = n.entries.iter().map(|e| (&e.path, &e.hash)).collect();

    for (path, h_new) in &map_new {
        match map_old.get(path) {
            None => println!("ADDED   {path}"),
            Some(h_old) if *h_old != *h_new => println!("CHANGED {path}"),
            _ => {}
        }
    }
    for path in map_old.keys() {
        if !map_new.contains_key(path) {
            println!("REMOVED {path}");
        }
    }
    Ok(())
}
