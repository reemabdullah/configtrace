use anyhow::Result;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use super::models::*;

// ===== Shared helpers =====

fn write_key_change(stdout: &mut StandardStream, change: &KeyChange) -> Result<()> {
    match change.kind {
        KeyChangeKind::Added => {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
            write!(stdout, "+ {}", change.key)?;
            stdout.reset()?;
            if let Some(val) = &change.new_value {
                write!(stdout, " = {}", val)?;
            }
        }
        KeyChangeKind::Removed => {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
            write!(stdout, "- {}", change.key)?;
            stdout.reset()?;
            if let Some(val) = &change.old_value {
                write!(stdout, " = {}", val)?;
            }
        }
        KeyChangeKind::Changed => {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
            write!(stdout, "~ {}", change.key)?;
            stdout.reset()?;
            write!(
                stdout,
                ": {} -> {}",
                change.old_value.as_deref().unwrap_or(""),
                change.new_value.as_deref().unwrap_or("")
            )?;
        }
    }
    Ok(())
}

fn write_violation(
    stdout: &mut StandardStream,
    v: &crate::policy::models::Violation,
) -> Result<()> {
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
    write!(stdout, "VIOLATION")?;
    stdout.reset()?;
    writeln!(stdout, " [{}] {}: {}", v.severity, v.rule_id, v.message)?;
    Ok(())
}

// ===== Git Log Output =====

pub fn output_log_json(report: &GitLogReport, output_file: Option<&str>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if let Some(path) = output_file {
        std::fs::write(path, &json)?;
        println!("Wrote git log report to {}", path);
    } else {
        println!("{}", json);
    }
    Ok(())
}

pub fn output_log_terminal(report: &GitLogReport) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    writeln!(&mut stdout)?;
    stdout.set_color(ColorSpec::new().set_bold(true))?;
    writeln!(&mut stdout, "Config Change History")?;
    stdout.reset()?;

    if let Some(path) = &report.path_filter {
        writeln!(&mut stdout, "  Path filter: {}", path)?;
    }
    writeln!(
        &mut stdout,
        "  Commits with config changes: {}\n",
        report.commits_analyzed
    )?;

    if report.commits.is_empty() {
        writeln!(&mut stdout, "  No config changes found.")?;
        writeln!(&mut stdout)?;
        return Ok(());
    }

    for commit in &report.commits {
        // Commit header
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
        write!(&mut stdout, "{}", commit.commit_hash)?;
        stdout.reset()?;

        let first_line = commit.message.lines().next().unwrap_or("");
        writeln!(
            &mut stdout,
            " - {} ({}, {})",
            first_line, commit.author, commit.date
        )?;

        for file in &commit.files {
            writeln!(&mut stdout, "  File: {}", file.path)?;
            for change in &file.changes {
                write!(&mut stdout, "    ")?;
                write_key_change(&mut stdout, change)?;
                writeln!(&mut stdout)?;
            }
            for v in &file.violations {
                write!(&mut stdout, "    ")?;
                write_violation(&mut stdout, v)?;
            }
        }
        writeln!(&mut stdout)?;
    }

    Ok(())
}

// ===== Git Diff Output =====

pub fn output_diff_json(report: &GitDiffReport, output_file: Option<&str>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if let Some(path) = output_file {
        std::fs::write(path, &json)?;
        println!("Wrote git diff report to {}", path);
    } else {
        println!("{}", json);
    }
    Ok(())
}

pub fn output_diff_terminal(report: &GitDiffReport) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    writeln!(&mut stdout)?;
    stdout.set_color(ColorSpec::new().set_bold(true))?;
    writeln!(
        &mut stdout,
        "Config diff: {} .. {}",
        report.ref_from, report.ref_to
    )?;
    stdout.reset()?;

    if let Some(path) = &report.path_filter {
        writeln!(&mut stdout, "  Path filter: {}", path)?;
    }
    writeln!(&mut stdout)?;

    if report.files.is_empty() {
        writeln!(&mut stdout, "  No config changes found.")?;
        writeln!(&mut stdout)?;
        return Ok(());
    }

    for file in &report.files {
        writeln!(&mut stdout, "File: {}", file.path)?;
        for change in &file.changes {
            write!(&mut stdout, "  ")?;
            write_key_change(&mut stdout, change)?;
            writeln!(&mut stdout)?;
        }
        for v in &file.violations {
            write!(&mut stdout, "  ")?;
            write_violation(&mut stdout, v)?;
        }
        writeln!(&mut stdout)?;
    }

    // Summary
    writeln!(&mut stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
    stdout.set_color(ColorSpec::new().set_bold(true))?;
    writeln!(&mut stdout, "Summary:")?;
    stdout.reset()?;
    writeln!(
        &mut stdout,
        "  Files changed: {}",
        report.total_files_changed
    )?;
    writeln!(&mut stdout, "  Keys added:    {}", report.total_keys_added)?;
    writeln!(
        &mut stdout,
        "  Keys removed:  {}",
        report.total_keys_removed
    )?;
    writeln!(
        &mut stdout,
        "  Keys changed:  {}",
        report.total_keys_changed
    )?;
    writeln!(&mut stdout)?;

    Ok(())
}
