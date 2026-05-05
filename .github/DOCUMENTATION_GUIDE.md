# Advanced Security Documentation Guide

## Documentation Structure

```
docs/
├── README.md                  # Navigation hub
├── architecture.md            # System design (HLD + LLD merged)
├── workflows.md               # Runtime operational flows
├── DATA_FLOW.md               # Input/output paths, log generation, alert lifecycle
├── SECURITY_MODEL.md          # Policies, threats, enforcement, trust boundaries
├── TOOLS.md                   # Complete function/script/API catalog
├── troubleshooting.md         # Diagnosis, decision trees, RCA
├── developer-playbook.md      # Commands & validation
├── onboarding.md              # New engineer guide
└── reference/
    ├── api-reference.md       # DML/Internal API reference
    ├── feature-catalog.md     # Feature-by-feature catalog
    └── tr181-matrix.md        # TR-181 parameter ownership

.github/
├── knowledge/
│   └── reference-data.md     # Enums, syscfg keys, build flags, failure patterns (AI-focused)
├── skills/                    # AI skill definitions
└── instructions/              # Language-specific coding guidelines
```

## Conventions

### Where to Put Documentation

| Type | Location | Audience |
|------|----------|----------|
| System design, architecture | `docs/architecture.md` | Engineers, reviewers |
| Operational flows | `docs/workflows.md` | Engineers |
| Data flow, I/O paths, alerts | `docs/DATA_FLOW.md` | Engineers, integrators |
| Security policies, threats | `docs/SECURITY_MODEL.md` | Security reviewers, engineers |
| Function/script/API catalog | `docs/TOOLS.md` | Engineers, AI agents |
| Troubleshooting, RCA | `docs/troubleshooting.md` | On-call, support |
| CLI commands, validation | `docs/developer-playbook.md` | Engineers |
| API contracts | `docs/reference/` | Engineers, integrators |
| Feature catalog | `docs/reference/feature-catalog.md` | Engineers |
| Enums, syscfg keys, patterns | `.github/knowledge/` | AI agents |
| Coding standards | `.github/instructions/` | AI agents, engineers |

### Style Rules

1. **Link, don't duplicate** — Reference existing docs instead of copying content
2. **One source of truth** — Each fact lives in exactly one file
3. **Mermaid for diagrams** — Use mermaid code blocks for all diagrams
4. **Tables for structured data** — Prefer tables over prose for enums, flags, mappings
5. **Code blocks for commands** — Always use fenced code blocks with language tag
6. **Cross-references** — Use paths relative to the current file. For example, from a file in `docs/` link with `[architecture](architecture.md)`, and from a file in `.github/` link with `[architecture](../docs/architecture.md)`.

### When to Update

- New RFC toggle or feature parameter → `docs/reference/feature-catalog.md` + `docs/reference/tr181-matrix.md`
- New DML handler → `docs/reference/api-reference.md` + `docs/TOOLS.md`
- New Init/DeInit function → `docs/reference/api-reference.md` + `docs/TOOLS.md` + `.github/knowledge/reference-data.md`
- New data flow path or input source → `docs/DATA_FLOW.md`
- New trust boundary or security policy → `docs/SECURITY_MODEL.md`
- New enforcement mechanism or threat detection → `docs/SECURITY_MODEL.md`
- New telemetry marker or alert threshold → `docs/DATA_FLOW.md`
- New shell script function → `docs/TOOLS.md`
- New build flag → `.github/knowledge/reference-data.md`
- New failure pattern → `.github/knowledge/reference-data.md` + `docs/troubleshooting.md`
- New diagnostic command → `docs/developer-playbook.md`
- New syscfg key → `.github/knowledge/reference-data.md`
- Architecture change → `docs/architecture.md`

### Quality Checklist

- [ ] No broken cross-references
- [ ] No duplicated content across files
- [ ] All code examples are correct and runnable
- [ ] Diagrams render in GitHub markdown preview
- [ ] New content linked from `docs/README.md` if top-level
- [ ] Function names match actual source code (verify with grep)
- [ ] Script flags match actual `start_adv_security.sh` arguments
