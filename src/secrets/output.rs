use anyhow::Result;
use std::fs;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use crate::models::{SecretReport, Severity};

/// Output results as JSON
pub fn output_json(report: &SecretReport, output_file: Option<&str>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;

    if let Some(file_path) = output_file {
        fs::write(file_path, json)?;
        println!("Wrote JSON report to {}", file_path);
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Output results to terminal with colors
pub fn output_terminal(report: &SecretReport) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    // Header
    writeln!(&mut stdout, "\nScanning for secrets in directory...")?;
    writeln!(&mut stdout)?;

    if report.total_findings == 0 {
        let mut spec = ColorSpec::new();
        spec.set_fg(Some(Color::Green)).set_bold(true);
        stdout.set_color(&spec)?;
        writeln!(&mut stdout, "No secrets found!")?;
        stdout.reset()?;

        writeln!(&mut stdout, "  Files scanned: {}", report.total_files)?;
        return Ok(());
    }

    // Display findings
    for file in &report.files {
        writeln!(&mut stdout, "File: {}", file.path)?;

        for finding in &file.findings {
            write!(&mut stdout, "  ")?;

            // Severity icon and color
            match finding.severity {
                Severity::Critical => {
                    let mut spec = ColorSpec::new();
                    spec.set_fg(Some(Color::Red)).set_bold(true);
                    stdout.set_color(&spec)?;
                    write!(&mut stdout, "CRITICAL")?;
                }
                Severity::High => {
                    let mut spec = ColorSpec::new();
                    spec.set_fg(Some(Color::Yellow)).set_bold(true);
                    stdout.set_color(&spec)?;
                    write!(&mut stdout, "HIGH")?;
                }
            }
            stdout.reset()?;

            writeln!(&mut stdout, ": {}", finding.matched_pattern)?;
            writeln!(&mut stdout, "    Line: {}", finding.line)?;
            writeln!(&mut stdout, "    Snippet: {}", finding.snippet)?;
            writeln!(&mut stdout)?;
        }
    }

    // Summary
    writeln!(&mut stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
    writeln!(&mut stdout, "Summary:")?;
    writeln!(&mut stdout, "  Files scanned: {}", report.total_files)?;
    writeln!(
        &mut stdout,
        "  Files with secrets: {}",
        report.files_with_secrets
    )?;
    writeln!(&mut stdout, "  Total findings: {}", report.total_findings)?;
    writeln!(&mut stdout)?;

    write!(&mut stdout, "  By severity: ")?;

    if report.critical_count > 0 {
        let mut spec = ColorSpec::new();
        spec.set_fg(Some(Color::Red)).set_bold(true);
        stdout.set_color(&spec)?;
        write!(&mut stdout, "Critical: {}", report.critical_count)?;
        stdout.reset()?;
        write!(&mut stdout, "  |  ")?;
    }

    if report.high_count > 0 {
        let mut spec = ColorSpec::new();
        spec.set_fg(Some(Color::Yellow)).set_bold(true);
        stdout.set_color(&spec)?;
        write!(&mut stdout, "High: {}", report.high_count)?;
        stdout.reset()?;
    }

    writeln!(&mut stdout)?;
    writeln!(&mut stdout)?;

    // Final message
    let mut spec = ColorSpec::new();
    spec.set_fg(Some(Color::Red)).set_bold(true);
    stdout.set_color(&spec)?;
    writeln!(&mut stdout, "Secrets detected!")?;
    stdout.reset()?;

    Ok(())
}
