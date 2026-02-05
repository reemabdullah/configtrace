use anyhow::Result;
use std::fs;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use super::models::{PolicyReport, PolicySeverity};

/// Output results as JSON.
pub fn output_json(report: &PolicyReport, output_file: Option<&str>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if let Some(file_path) = output_file {
        fs::write(file_path, json)?;
        println!("Wrote policy report to {}", file_path);
    } else {
        println!("{}", json);
    }
    Ok(())
}

/// Output results to terminal with colors.
pub fn output_terminal(report: &PolicyReport) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    // Header
    writeln!(&mut stdout, "\nEvaluating policy: {}", report.policy_name)?;
    if let Some(desc) = &report.policy_description {
        writeln!(&mut stdout, "  {}", desc)?;
    }
    writeln!(&mut stdout)?;

    if report.total_violations == 0 {
        let mut spec = ColorSpec::new();
        spec.set_fg(Some(Color::Green)).set_bold(true);
        stdout.set_color(&spec)?;
        writeln!(&mut stdout, "All checks passed!")?;
        stdout.reset()?;
        writeln!(
            &mut stdout,
            "  Files checked: {}",
            report.total_files_checked
        )?;
        return Ok(());
    }

    // Display violations grouped by file
    for file in &report.files {
        writeln!(&mut stdout, "File: {}", file.path)?;

        for violation in &file.violations {
            write!(&mut stdout, "  ")?;
            write_severity(&mut stdout, &violation.severity)?;
            stdout.reset()?;
            writeln!(&mut stdout, " [{}]: {}", violation.rule_id, violation.message)?;
            if let Some(desc) = &violation.rule_description {
                writeln!(&mut stdout, "    Rule: {}", desc)?;
            }
            writeln!(&mut stdout, "    Key: {}", violation.key)?;
            writeln!(&mut stdout)?;
        }
    }

    // Summary
    writeln!(&mut stdout, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
    writeln!(&mut stdout, "Summary:")?;
    writeln!(&mut stdout, "  Policy: {}", report.policy_name)?;
    writeln!(
        &mut stdout,
        "  Files checked: {}",
        report.total_files_checked
    )?;
    writeln!(
        &mut stdout,
        "  Files with violations: {}",
        report.files_with_violations
    )?;
    writeln!(
        &mut stdout,
        "  Total violations: {}",
        report.total_violations
    )?;
    writeln!(&mut stdout)?;

    write!(&mut stdout, "  By severity: ")?;
    let counts = [
        (PolicySeverity::Critical, report.critical_count, Color::Red),
        (PolicySeverity::High, report.high_count, Color::Yellow),
        (PolicySeverity::Medium, report.medium_count, Color::Cyan),
        (PolicySeverity::Low, report.low_count, Color::Blue),
    ];
    let mut first = true;
    for (sev, count, color) in &counts {
        if *count > 0 {
            if !first {
                write!(&mut stdout, "  |  ")?;
            }
            let mut spec = ColorSpec::new();
            spec.set_fg(Some(*color)).set_bold(true);
            stdout.set_color(&spec)?;
            write!(&mut stdout, "{}: {}", sev, count)?;
            stdout.reset()?;
            first = false;
        }
    }
    writeln!(&mut stdout)?;
    writeln!(&mut stdout)?;

    // Final verdict
    let mut spec = ColorSpec::new();
    spec.set_fg(Some(Color::Red)).set_bold(true);
    stdout.set_color(&spec)?;
    writeln!(&mut stdout, "Policy violations detected!")?;
    stdout.reset()?;

    Ok(())
}

fn write_severity(stdout: &mut StandardStream, severity: &PolicySeverity) -> Result<()> {
    let (color, label) = match severity {
        PolicySeverity::Critical => (Color::Red, "CRITICAL"),
        PolicySeverity::High => (Color::Yellow, "HIGH"),
        PolicySeverity::Medium => (Color::Cyan, "MEDIUM"),
        PolicySeverity::Low => (Color::Blue, "LOW"),
    };
    let mut spec = ColorSpec::new();
    spec.set_fg(Some(color)).set_bold(true);
    stdout.set_color(&spec)?;
    write!(stdout, "{}", label)?;
    Ok(())
}
