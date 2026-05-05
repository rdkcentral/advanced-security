---
description: "Generate docs README navigation hub for Advanced Security component modeled after Cellular Manager docs README"
agent: "agent"
---

# Generate Docs README

Generate a `docs/README.md` navigation hub for the **Advanced Security (CcspAdvSecurity)** component.

## Reference

Use the Cellular Manager docs README as the structural template:
[README.md](../../../cellular/cellular-manager/docs/README.md)

## Required Sections

1. **Quick Links** — Table mapping document name → content summary:
   - Architecture → System design, components, feature modules, threading, dependencies, build flags
   - Workflows → Component startup, feature enable/disable, WebConfig processing, RFC toggles, recovery
   - Troubleshooting → Decision trees, log signatures, diagnostic commands, RCA workflow
   - Developer Playbook → Shell commands for debugging, TR-181 validation, feature testing
   - Onboarding → First 30 minutes new engineer guide
   - TR-181 Matrix → Parameter-to-code ownership map
   - API Reference → Internal API signatures and contracts
   - Feature Catalog → Feature modules, RFC toggles, WebConfig integration

2. **Structure** — Directory tree showing docs layout:
   ```
   docs/
   ├── README.md
   ├── architecture.md
   ├── workflows.md
   ├── troubleshooting.md
   ├── developer-playbook.md
   ├── onboarding.md
   └── reference/
       ├── tr181-matrix.md
       ├── api-reference.md
       └── feature-catalog.md
   ```

3. **Component Overview** — Brief description of CcspAdvSecurity: plugin-based TR-181 interface for security features (DeviceFingerPrint, SafeBrowsing, Softflowd, Parental Controls, Privacy Protection), coordinating with the Security Agent for enforcement

4. **Key Source Files** — List of critical source files with their roles

5. **Build & Test** — Commands for building and running unit tests

6. **Reading Order** — Recommended order for new engineers

## Style Guidelines

- Keep it concise — this is a navigation hub, not a deep-dive
- All document references should be relative markdown links
- Match the format and brevity of the Cellular Manager docs README
