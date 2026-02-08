use anyhow::Result;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use super::models::{AuditReport, RiskLevel};

// ===== Terminal Output =====

pub fn output_terminal(report: &AuditReport) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    // Header
    writeln!(&mut stdout)?;
    stdout.set_color(ColorSpec::new().set_bold(true))?;
    writeln!(&mut stdout, "ConfigTrace Audit Report")?;
    writeln!(&mut stdout, "========================")?;
    stdout.reset()?;
    writeln!(
        &mut stdout,
        "Generated: {}",
        report.overview.generated_at
    )?;
    writeln!(&mut stdout, "Path: {}", report.overview.path)?;
    writeln!(
        &mut stdout,
        "Files: {} ({} yaml, {} json, {} toml)",
        report.overview.total_files,
        report.overview.yaml_count,
        report.overview.json_count,
        report.overview.toml_count
    )?;

    // Config Inventory
    writeln!(&mut stdout)?;
    write_section_header(&mut stdout, "Config Inventory")?;
    for entry in &report.inventory {
        writeln!(
            &mut stdout,
            "  {:<40} {}",
            entry.path,
            &entry.hash[..12.min(entry.hash.len())]
        )?;
    }

    // Secret Findings
    if let Some(secrets) = &report.secrets {
        writeln!(&mut stdout)?;
        write_section_header(&mut stdout, "Secret Findings")?;
        if secrets.total_findings == 0 {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
            writeln!(&mut stdout, "  No secrets found.")?;
            stdout.reset()?;
        } else {
            if secrets.critical_count > 0 {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
                write!(&mut stdout, "  CRITICAL: {}", secrets.critical_count)?;
                stdout.reset()?;
                writeln!(&mut stdout)?;
            }
            if secrets.high_count > 0 {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
                write!(&mut stdout, "  HIGH: {}", secrets.high_count)?;
                stdout.reset()?;
                writeln!(&mut stdout)?;
            }
            writeln!(&mut stdout)?;
            for file in &secrets.files {
                writeln!(&mut stdout, "  {}:", file.path)?;
                for finding in &file.findings {
                    let color = match finding.severity {
                        crate::models::Severity::Critical => Color::Red,
                        crate::models::Severity::High => Color::Yellow,
                    };
                    write!(&mut stdout, "    ")?;
                    stdout.set_color(ColorSpec::new().set_fg(Some(color)))?;
                    write!(&mut stdout, "[{:?}]", finding.severity)?;
                    stdout.reset()?;
                    writeln!(
                        &mut stdout,
                        " Line {}: {} - {}",
                        finding.line, finding.matched_pattern, finding.snippet
                    )?;
                }
            }
        }
    }

    // Policy Violations
    if let Some(policy) = &report.policy {
        writeln!(&mut stdout)?;
        write_section_header(&mut stdout, "Policy Violations")?;
        writeln!(&mut stdout, "  Policy: {}", policy.policy_name)?;
        if policy.total_violations == 0 {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
            writeln!(&mut stdout, "  All checks passed.")?;
            stdout.reset()?;
        } else {
            write!(&mut stdout, "  ")?;
            write_severity_counts(
                &mut stdout,
                policy.critical_count,
                policy.high_count,
                policy.medium_count,
                policy.low_count,
            )?;
            writeln!(&mut stdout)?;
            writeln!(&mut stdout)?;
            for file in &policy.files {
                writeln!(&mut stdout, "  {}:", file.path)?;
                for v in &file.violations {
                    let color = match v.severity {
                        crate::policy::models::PolicySeverity::Critical => Color::Red,
                        crate::policy::models::PolicySeverity::High => Color::Yellow,
                        crate::policy::models::PolicySeverity::Medium => Color::Cyan,
                        crate::policy::models::PolicySeverity::Low => Color::Blue,
                    };
                    write!(&mut stdout, "    ")?;
                    stdout.set_color(ColorSpec::new().set_fg(Some(color)))?;
                    write!(&mut stdout, "[{}]", v.severity)?;
                    stdout.reset()?;
                    writeln!(&mut stdout, " {}: {}", v.rule_id, v.message)?;
                }
            }
        }
    }

    // Git Changes
    if let Some(git) = &report.git_changes {
        writeln!(&mut stdout)?;
        write_section_header(
            &mut stdout,
            &format!("Recent Changes (last {} commits)", git.commits_analyzed),
        )?;
        for commit in &git.commits {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
            write!(&mut stdout, "  {}", commit.commit_hash)?;
            stdout.reset()?;

            let first_line = commit.message.lines().next().unwrap_or("");
            writeln!(&mut stdout, " - {} ({}, {})", first_line, commit.author, &commit.date[..10.min(commit.date.len())])?;

            for file in &commit.files {
                let total = file.keys_added + file.keys_removed + file.keys_changed;
                writeln!(&mut stdout, "    {}: ~{} keys changed", file.path, total)?;
            }
        }
    }

    // Risk Summary
    writeln!(&mut stdout)?;
    write_section_header(&mut stdout, "Risk Summary")?;
    let risk_color = match report.risk_level {
        RiskLevel::Pass => Color::Green,
        RiskLevel::Warn => Color::Yellow,
        RiskLevel::Fail => Color::Red,
    };
    write!(&mut stdout, "  ")?;
    stdout.set_color(ColorSpec::new().set_fg(Some(risk_color)).set_bold(true))?;
    write!(&mut stdout, "{}", report.risk_level)?;
    stdout.reset()?;
    writeln!(&mut stdout, " -- {}", report.risk_summary)?;
    writeln!(&mut stdout)?;

    Ok(())
}

fn write_section_header(stdout: &mut StandardStream, title: &str) -> Result<()> {
    stdout.set_color(ColorSpec::new().set_bold(true))?;
    writeln!(stdout, "--- {} ---", title)?;
    stdout.reset()?;
    Ok(())
}

fn write_severity_counts(
    stdout: &mut StandardStream,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
) -> Result<()> {
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    write!(stdout, "CRITICAL: {}", critical)?;
    stdout.reset()?;
    write!(stdout, " | ")?;
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
    write!(stdout, "HIGH: {}", high)?;
    stdout.reset()?;
    write!(stdout, " | ")?;
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)))?;
    write!(stdout, "MEDIUM: {}", medium)?;
    stdout.reset()?;
    write!(stdout, " | ")?;
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue)))?;
    write!(stdout, "LOW: {}", low)?;
    stdout.reset()?;
    Ok(())
}

// ===== JSON Output =====

pub fn output_json(report: &AuditReport, output_file: Option<&str>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if let Some(path) = output_file {
        std::fs::write(path, &json)?;
        println!("Wrote audit report to {}", path);
    } else {
        println!("{}", json);
    }
    Ok(())
}

// ===== Markdown Output =====

pub fn output_markdown(report: &AuditReport, output_file: Option<&str>) -> Result<()> {
    let mut md = String::new();

    // Header
    md.push_str("# ConfigTrace Audit Report\n\n");
    md.push_str(&format!(
        "**Generated:** {} | **Path:** `{}` | **Files:** {} ({} yaml, {} json, {} toml)\n\n",
        report.overview.generated_at,
        report.overview.path,
        report.overview.total_files,
        report.overview.yaml_count,
        report.overview.json_count,
        report.overview.toml_count,
    ));

    // Config Inventory
    md.push_str("## Config Inventory\n\n");
    md.push_str("| File | SHA256 | Format |\n");
    md.push_str("|------|--------|--------|\n");
    for entry in &report.inventory {
        md.push_str(&format!(
            "| {} | `{}` | {} |\n",
            entry.path,
            &entry.hash[..12.min(entry.hash.len())],
            entry.format
        ));
    }
    md.push('\n');

    // Secret Findings
    if let Some(secrets) = &report.secrets {
        md.push_str("## Secret Findings\n\n");
        if secrets.total_findings == 0 {
            md.push_str("No secrets found.\n\n");
        } else {
            md.push_str("| Severity | Count |\n");
            md.push_str("|----------|-------|\n");
            if secrets.critical_count > 0 {
                md.push_str(&format!("| Critical | {} |\n", secrets.critical_count));
            }
            if secrets.high_count > 0 {
                md.push_str(&format!("| High | {} |\n", secrets.high_count));
            }
            md.push_str(&format!(
                "\n**Total:** {} findings in {} files\n\n",
                secrets.total_findings, secrets.files_with_secrets
            ));

            for file in &secrets.files {
                md.push_str(&format!("### `{}`\n\n", file.path));
                for finding in &file.findings {
                    md.push_str(&format!(
                        "- **[{:?}]** Line {}: {} - `{}`\n",
                        finding.severity,
                        finding.line,
                        finding.matched_pattern,
                        finding.snippet
                    ));
                }
                md.push('\n');
            }
        }
    }

    // Policy Violations
    if let Some(policy) = &report.policy {
        md.push_str("## Policy Violations\n\n");
        md.push_str(&format!("**Policy:** {}\n\n", policy.policy_name));
        if policy.total_violations == 0 {
            md.push_str("All checks passed.\n\n");
        } else {
            md.push_str("| Severity | Count |\n");
            md.push_str("|----------|-------|\n");
            md.push_str(&format!("| Critical | {} |\n", policy.critical_count));
            md.push_str(&format!("| High | {} |\n", policy.high_count));
            md.push_str(&format!("| Medium | {} |\n", policy.medium_count));
            md.push_str(&format!("| Low | {} |\n", policy.low_count));
            md.push_str(&format!(
                "\n**Total:** {} violations in {} files\n\n",
                policy.total_violations, policy.files_with_violations
            ));

            for file in &policy.files {
                md.push_str(&format!("### `{}`\n\n", file.path));
                for v in &file.violations {
                    md.push_str(&format!(
                        "- **[{}]** `{}`: {}\n",
                        v.severity, v.rule_id, v.message
                    ));
                }
                md.push('\n');
            }
        }
    }

    // Git Changes
    if let Some(git) = &report.git_changes {
        md.push_str(&format!(
            "## Recent Changes (last {} commits)\n\n",
            git.commits_analyzed
        ));
        for commit in &git.commits {
            let first_line = commit.message.lines().next().unwrap_or("");
            md.push_str(&format!(
                "- **{}** - {} ({}, {})\n",
                commit.commit_hash,
                first_line,
                commit.author,
                &commit.date[..10.min(commit.date.len())]
            ));
            for file in &commit.files {
                let total = file.keys_added + file.keys_removed + file.keys_changed;
                md.push_str(&format!("  - `{}`: ~{} keys changed\n", file.path, total));
            }
        }
        md.push('\n');
    }

    // Risk Summary
    md.push_str("## Risk Summary\n\n");
    let icon = match report.risk_level {
        RiskLevel::Pass => "PASS",
        RiskLevel::Warn => "WARN",
        RiskLevel::Fail => "FAIL",
    };
    md.push_str(&format!(
        "**{}** -- {}\n",
        icon, report.risk_summary
    ));

    // Output
    if let Some(path) = output_file {
        std::fs::write(path, &md)?;
        println!("Wrote audit report to {}", path);
    } else {
        print!("{}", md);
    }

    Ok(())
}
