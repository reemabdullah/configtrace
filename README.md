# 🔐 ConfigTrace

![status](https://img.shields.io/badge/status-WIP-yellow)
![license](https://img.shields.io/badge/license-MIT-blue)
![built-with](https://img.shields.io/badge/built%20with-Rust-orange)

A lightweight Rust CLI to **scan, diff, and report configuration files** (YAML / JSON / TOML).  
Built for teams that care about **security governance** and **config integrity**.

---

## 🚧 Status

Work in progress (v0.1)

---

## ⚙️ Quick Start

```bash
# Scan directory and create snapshot
configtrace scan ./infra --out snapshot.json

# Compare two snapshots
configtrace diff old.json new.json

# Generate unified audit report (inventory, secrets, policy, git)
configtrace report ./infra
configtrace report ./infra --policy production.yaml
configtrace report ./infra --format markdown --output audit.md
configtrace report ./infra --format json --output audit.json

# Scan for exposed secrets
configtrace secrets ./infra
configtrace secrets ./infra --format=json --output=secrets.json

# Check configs against a policy
configtrace policy check ./infra --policy production.yaml
configtrace policy check ./infra --policy production.yaml --format json

# Validate a policy file
configtrace policy validate production.yaml

# Show config change history across git commits
configtrace git log
configtrace git log src/configs/ --limit 20

# Compare configs between two git refs at the key level
configtrace git diff HEAD~3 HEAD
configtrace git diff main feature-branch src/configs/

# Git commands with policy audit
configtrace git log --policy production.yaml
configtrace git diff v1.0 v2.0 --policy production.yaml --format json
```

---

## 🔍 Secret Detection

ConfigTrace includes built-in secret detection to identify exposed credentials in configuration files.

### Detected Secret Types

- **AWS Access Keys & Secret Keys** (Critical)
- **GCP Service Account Keys** (Critical)
- **Private Keys** (RSA, EC, OpenSSH) (Critical)
- **GitHub Tokens** (Critical)
- **Database Connection Strings** (Critical)
- **Generic Passwords** (Critical)
- **API Keys** (High)
- **JWT Tokens** (High)

### Output Formats

**Terminal (colorized):**

```bash
configtrace secrets ./infra
```

**JSON (for automation):**

```bash
configtrace secrets ./infra --format=json --output=secrets.json
```

### Exit Codes

- `0` - No secrets found
- `1` - Secrets detected
- `2` - Error (file not found, permissions, etc.)

---

## 📋 Policy Engine

Define security and governance rules in YAML policy files and validate configs against them.

### Rule Types

| Type              | Description                         |
| ----------------- | ----------------------------------- |
| `required_key`    | A key must exist in the config      |
| `forbidden_key`   | A key must NOT exist                |
| `value_match`     | Value must match a regex pattern    |
| `value_enum`      | Value must be one of allowed values |
| `forbidden_value` | A specific key=value must not exist |

### Example Policy File

```yaml
name: "production-security"
description: "Security policies for production"
rules:
  - id: no-debug-mode
    description: "Debug must be disabled"
    severity: critical
    check:
      type: forbidden_value
      key: "debug"
      value: "true"

  - id: valid-log-level
    description: "Log level must be standard"
    severity: medium
    check:
      type: value_enum
      key: "logging.level"
      values: ["info", "warn", "error"]

  - id: eu-region-only
    description: "Only EU regions permitted"
    severity: critical
    pattern: "*.yaml"
    check:
      type: value_match
      key: "aws.region"
      regex: "^eu-(west|north)-[12]$"
```

### Severity Levels

- **Critical** - Security-breaking violations
- **High** - Important governance violations
- **Medium** - Best-practice violations
- **Low** - Informational findings

### Exit Codes

- `0` - All checks passed
- `1` - Violations found
- `2` - Error (invalid policy, parse failure)

---

## 🔀 Git Integration

Track config changes across git history at the **key level** — see exactly which config keys were added, removed, or changed in each commit.

### Git Log

Show config change history across recent commits:

```bash
configtrace git log
configtrace git log src/configs/ --limit 20
```

Output shows per-commit, per-file, per-key changes:

```
abc1234 - Update database config (Alice, 2025-01-15)
  File: config/database.yaml
    ~ database.host: localhost -> db.prod.internal
    + database.pool_size = 20
```

### Git Diff

Compare configs between two git refs (commits, branches, tags):

```bash
configtrace git diff HEAD~3 HEAD
configtrace git diff main feature-branch src/configs/
```

### Policy Audit on Git History

Use `--policy` to check historical configs against policy rules:

```bash
configtrace git log --policy production.yaml
configtrace git diff v1.0 v2.0 --policy production.yaml
```

Violations are shown inline and exit code is `1` when violations are found.

### Output Formats

Both commands support `--format json` and `--output file`:

```bash
configtrace git log --format json --output git-log.json
configtrace git diff HEAD~1 HEAD --format json
```

### Exit Codes

- `0` - No policy violations (or no `--policy` flag)
- `1` - Policy violations found
- `2` - Error (not a git repo, invalid ref, etc.)

---

## 📊 Unified Audit Report

Generate a comprehensive security audit report that combines all analysis into a single view:

- **Config Inventory** — all files with SHA256 hashes
- **Secret Findings** — exposed credentials with severity
- **Policy Violations** — governance rule failures (with `--policy`)
- **Recent Git Changes** — last 5 commits that touched configs
- **Risk Summary** — overall PASS/WARN/FAIL status

```bash
# Terminal output (default)
configtrace report ./configs

# With policy evaluation
configtrace report ./configs --policy production.yaml

# Markdown for documentation
configtrace report ./configs --format markdown --output audit.md

# JSON for CI/CD pipelines
configtrace report ./configs --format json --output audit.json
```

### Risk Levels

- **PASS** — No issues found
- **WARN** — Non-critical findings (high secrets, medium policy violations)
- **FAIL** — Critical secrets or policy violations detected

### Exit Codes

- `0` — PASS
- `1` — FAIL (critical findings)

---

## 💡 Why

ConfigTrace helps answer:

> “Who changed what, when, and where — and is it compliant?”

A simple way to track and audit configuration drifts across GCP or Kubernetes without heavy enterprise tooling.

---

## 🧱 Stack

Rust · Clap · Serde · SHA2 · Regex · Termcolor · Serde YAML · TOML · Git2 · GitHub Actions

---

## 📜 License

MIT © [Reem Abdullah](https://github.com/reemabdullah) · [LinkedIn](https://linkedin.com/in/reemalsobaiee)
