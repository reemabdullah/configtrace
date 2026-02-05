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

# Generate Markdown report
configtrace report --snapshot snapshot.json --out report.md

# Scan for exposed secrets
configtrace secrets ./infra
configtrace secrets ./infra --format=json --output=secrets.json

# Check configs against a policy
configtrace policy check ./infra --policy production.yaml
configtrace policy check ./infra --policy production.yaml --format json

# Validate a policy file
configtrace policy validate production.yaml
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

## 💡 Why

ConfigTrace helps answer:

> “Who changed what, when, and where — and is it compliant?”

A simple way to track and audit configuration drifts across GCP or Kubernetes without heavy enterprise tooling.

---

## 🧱 Stack

Rust · Clap · Serde · SHA2 · Regex · Termcolor · Serde YAML · TOML · GitHub Actions

---

## 📜 License

MIT © [Reem Abdullah](https://github.com/reemabdullah) · [LinkedIn](https://linkedin.com/in/reemalsobaiee)
