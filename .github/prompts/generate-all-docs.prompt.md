---
description: "Generate complete documentation suite for Advanced Security component — all docs in one pass, modeled after Cellular Manager docs"
agent: "agent"
---

# Generate Complete Documentation Suite

Generate the full documentation suite for the **Advanced Security (CcspAdvSecurity)** component, creating all doc files in a single pass. Each doc should match the structure and depth of its Cellular Manager counterpart.

## Reference (Cellular Manager docs to model after)

- [docs/README.md](../../../cellular/cellular-manager/docs/README.md) — Navigation hub
- [docs/architecture.md](../../../cellular/cellular-manager/docs/architecture.md) — System design
- [docs/workflows.md](../../../cellular/cellular-manager/docs/workflows.md) — Runtime flows
- [docs/troubleshooting.md](../../../cellular/cellular-manager/docs/troubleshooting.md) — Decision trees, log signatures
- [docs/developer-playbook.md](../../../cellular/cellular-manager/docs/developer-playbook.md) — Debug commands
- [docs/onboarding.md](../../../cellular/cellular-manager/docs/onboarding.md) — First 30 minutes
- [docs/reference/tr181-matrix.md](../../../cellular/cellular-manager/docs/reference/tr181-matrix.md) — TR-181 ownership
- [docs/reference/hal-api.md](../../../cellular/cellular-manager/docs/reference/hal-api.md) — API reference
- [docs/reference/callbacks.md](../../../cellular/cellular-manager/docs/reference/callbacks.md) — Feature/callback catalog

## Source Files to Analyze

Read **all** source files to extract accurate content:

- `source/AdvSecuritySsp/` — SSP bootstrap (ssp_main.c, ssp_action.c)
- `source/AdvSecurityDml/` — DML plugin, feature models, webconfig, helpers, DCL
- `scripts/` — advsec.sh, start_adv_security.sh, advsec_cpu_mem_recovery.sh, advsec_log_fp_status.sh
- `config/TR181-AdvSecurity.xml` — data model definition
- `source/test/` — unit tests
- `configure.ac` — build flags

## Files to Create

Create the `docs/` directory and `docs/reference/` subdirectory, then generate:

1. **`docs/README.md`** — Navigation hub with quick links, structure, component overview, build/test commands
2. **`docs/architecture.md`** — System overview diagram, components table, initialization sequence, feature modules, RFC flags, threading, IPC, build flags
3. **`docs/workflows.md`** — Sequence diagrams for: startup, feature enable/disable, RFC toggle, SafeBrowsing, WebConfig blob processing, WiFi DCL, CPU/memory recovery, shutdown
4. **`docs/troubleshooting.md`** — Quick triage checklist, log sources, log signature reference (from actual source strings), decision trees for common failures, triage methodology
5. **`docs/developer-playbook.md`** — Process control, log collection, TR-181 validation commands, Security Agent checks, WebConfig diagnostics, build/test commands
6. **`docs/onboarding.md`** — 30-minute time-boxed onboarding: mental model, file map, log signatures, first diagnostics, feature validation drill, triage exercise
7. **`docs/reference/tr181-matrix.md`** — Parameter-to-code ownership matrix for all TR-181 families, layer ownership, common tracebacks, change management guidance
8. **`docs/reference/api-reference.md`** — Internal API reference: lifecycle APIs, feature init/deinit, config get/set, DML catalog, WebConfig APIs, helper APIs, SSP APIs
9. **`docs/reference/feature-catalog.md`** — Feature module catalog: per-feature enable/disable flows, RFC toggle master table, WebConfig blob lifecycle, feature interaction matrix

## Critical Rules

- **Derive all content from source code** — do not invent features or APIs not present in the codebase
- **Use Mermaid diagrams** for architecture overview and workflow sequences
- **Extract actual log strings** from source for the signature reference
- **Use relative file links** for all source and doc cross-references
- **Match Cellular Manager doc depth** — each doc should be comparable in thoroughness
- **Cross-link between docs** — each doc should reference related docs where appropriate
