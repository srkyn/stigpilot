# STIGPilot Configuration

STIGPilot works without a config file. The built-in owner and tag rules are intentionally simple keyword matches so the output stays explainable.

Use a local TOML config when your team names, routing rules, or tags differ from the defaults.

## Create a Starter Config

```bash
stigpilot config-example --out stigpilot.toml
```

Use it with comparison commands:

```bash
stigpilot packet old.xml new.xml --out output/packet --config stigpilot.toml
stigpilot diff old.xml new.xml --out output/change-brief.md --csv output/backlog.csv --config stigpilot.toml
stigpilot batch old-stigs/ new-stigs/ --out output/portfolio --config stigpilot.toml
```

## Owner Rules

Owner rules route controls to a suggested team. Custom rules are checked before built-in defaults.

```toml
[[owner_rules]]
owner = "Windows Platform Team"
keywords = [
  "windows audit policy",
  "local security policy",
  "defender baseline",
  "gpresult",
]

[[owner_rules]]
owner = "Identity/IAM Team"
keywords = [
  "privileged account",
  "authentication",
  "account lifecycle",
  "password lockout",
]
```

Use specific phrases when you can. A broad keyword like `account` may route too much work to the same owner.

## Tag Rules

Tag rules add searchable labels to controls and ticket exports. Custom tags are merged with built-in tags.

```toml
[tag_rules]
"Privileged Access" = ["privileged account", "domain admin", "sudoers"]
"Evidence Refresh" = ["export applied", "validation artifact", "evidence package"]
"Policy Exception Review" = ["waiver", "exception", "documentable"]
```

Tags appear in:

- Markdown change briefs
- Remediation backlog CSVs
- Jira-friendly CSV labels
- ServiceNow-friendly CSV tag fields
- GitHub issue draft labels

## Practical Examples

Route browser policy work to endpoint engineering:

```toml
[[owner_rules]]
owner = "Endpoint Engineering"
keywords = ["chrome enterprise policy", "browser policy", "extensioninstallblocklist"]

[tag_rules]
"Browser Security" = ["chrome", "browser", "extensioninstallblocklist"]
```

Route Kubernetes controls to the platform team:

```toml
[[owner_rules]]
owner = "Platform Security"
keywords = ["kubernetes", "container", "pod security", "admission controller"]

[tag_rules]
"Container/Kubernetes" = ["kubernetes", "container", "pod security"]
```

Route database controls:

```toml
[[owner_rules]]
owner = "Database Operations"
keywords = ["postgresql", "oracle", "sql server", "mongodb", "database audit"]

[tag_rules]
"Database" = ["database", "postgresql", "oracle", "mongodb"]
```

## Validation Behavior

STIGPilot fails fast on malformed config files and prints a friendly config error.

Common mistakes:

- `owner_rules` must be a TOML array of tables.
- Each owner rule needs a non-empty `owner`.
- `keywords` must be a string or an array of strings.
- `tag_rules` must be a TOML table.
- Empty keywords are rejected.

## Tips

- Keep rules short and review them after the first packet.
- Prefer phrases found in check or fix text.
- Use `stigpilot summary input.xml --config stigpilot.toml` to preview owner routing.
- Use `stigpilot packet old.xml new.xml --owner "Team Name"` after tuning rules to generate a team-specific packet.
- Treat suggested owners as routing help, not authoritative assignment.
