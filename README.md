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
configtrace scan ./infra --out snapshot.json
configtrace diff old.json new.json
configtrace report --snapshot snapshot.json --out report.md
```

---

## 💡 Why

ConfigTrace helps answer:

> “Who changed what, when, and where — and is it compliant?”

A simple way to track and audit configuration drifts across GCP or Kubernetes without heavy enterprise tooling.

---

## 🧱 Stack

Rust · Clap · Serde · SHA2 · GitHub Actions

---

## 📜 License

MIT © [Reem Abdullah](https://linkedin.com/in/reemabdullah)
