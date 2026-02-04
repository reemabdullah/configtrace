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

## 💡 Why

ConfigTrace helps answer:

> “Who changed what, when, and where — and is it compliant?”

A simple way to track and audit configuration drifts across GCP or Kubernetes without heavy enterprise tooling.

---

## 🧱 Stack

Rust · Clap · Serde · SHA2 · Regex · Termcolor · GitHub Actions

---

## 📜 License

MIT © [Reem Abdullah](https://github.com/reemabdullah) · [LinkedIn](https://linkedin.com/in/reemalsobaiee)
