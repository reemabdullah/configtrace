# ConfigTrace

A tiny Rust CLI to **scan**, **diff**, and **report** configuration files (YAML/JSON/TOML) — helpful for governance and audits.

```bash
configtrace scan ./infra --out snapshot.json
configtrace diff old.json new.json
configtrace report --snapshot snapshot.json --out report.md
```

`Roadmap: Supabase/SQLite persistence · policy checks (e.g., “no public buckets”) · Nuxt dashboard`
