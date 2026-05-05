---
description: "Generate troubleshooting guide for Advanced Security component modeled after Cellular Manager troubleshooting doc"
agent: "agent"
---

# Generate Troubleshooting Documentation

Generate a comprehensive `docs/troubleshooting.md` for the **Advanced Security (CcspAdvSecurity)** component.

## Reference

Use the Cellular Manager troubleshooting doc as the structural template:
[troubleshooting.md](../../../cellular/cellular-manager/docs/troubleshooting.md)

## Source Files to Analyze

Read all source files under:

- [source/AdvSecurityDml/](../../source/AdvSecurityDml/) — DML handlers, helpers, webconfig, internal APIs
- [source/AdvSecuritySsp/](../../source/AdvSecuritySsp/) — SSP bootstrap, signal handling
- [scripts/](../../scripts/) — shell scripts for start, recovery, logging
- [config/TR181-AdvSecurity.xml](../../config/TR181-AdvSecurity.xml) — data model definition

Extract all log messages (`CcspTraceInfo`, `CcspTraceError`, `CcspTraceWarning`, `fprintf`, `syslog`, `AnscTraceWarning`) from source to build the log signature reference.

## Required Sections

1. **Quick Triage Checklist** — Numbered steps to check: process running, component registered with CR, Security Agent status, feature enablement states, WebConfig blob status, system resource usage
2. **Log Sources** — Table of log locations: journal, component log file paths, syslog, script output locations
3. **Log Signature Reference** — Tables organized by category:
   - Component lifecycle signatures (startup, registration, plugin load)
   - Feature enable/disable signatures (DeviceFingerPrint, SafeBrowsing, Softflowd, etc.)
   - WebConfig processing signatures (blob receive, decode, apply, rollback)
   - RFC toggle signatures
   - Error and failure signatures (privilege drop failure, bus connection failure, feature init failure)
   - Shell script signatures from `advsec.sh` and `start_adv_security.sh`
4. **Decision Trees** — ASCII/text decision trees for common failure scenarios:
   - 4.1: Component not starting (process not found)
   - 4.2: Feature not activating despite TR-181 set
   - 4.3: WebConfig blob rejected
   - 4.4: Security Agent not responding
   - 4.5: High CPU/memory from security features
   - 4.6: SafeBrowsing lookups failing
5. **Triage Pattern** — Standard 5-step triage methodology (find anomaly, locate context, map to code path, confirm expected behavior, classify root cause)
6. **Diagnostic Commands** — Shell commands for checking component health, TR-181 parameter values, Security Agent status, feature states, WebConfig status

## Style Guidelines

- Decision trees should use indented ASCII tree format matching the Cellular Manager style
- Log signatures must be derived from actual source code strings
- Include the code file where each signature originates
- Provide actionable next steps for each decision tree leaf node
