---
description: "Generate developer playbook for Advanced Security component modeled after Cellular Manager developer playbook"
agent: "agent"
---

# Generate Developer Playbook

Generate a practical `docs/developer-playbook.md` for the **Advanced Security (CcspAdvSecurity)** component.

## Reference

Use the Cellular Manager developer playbook as the structural template:
[developer-playbook.md](../../../cellular/cellular-manager/docs/developer-playbook.md)

## Source Files to Analyze

- [source/AdvSecuritySsp/](../../source/AdvSecuritySsp/) — process bootstrap
- [source/AdvSecurityDml/](../../source/AdvSecurityDml/) — DML and feature code
- [scripts/](../../scripts/) — operational scripts
- [config/TR181-AdvSecurity.xml](../../config/TR181-AdvSecurity.xml) — data model
- [source/test/](../../source/test/) — unit tests
- [configure.ac](../../configure.ac) — build configuration

## Required Sections

1. **Process and Service Control** — Commands to check process status, systemd service management, restart procedures
2. **Logs and Trace Collection** — Commands to collect journal logs, component-specific logs, grep for key events
3. **TR-181 Parameter Validation** — `dmcli` commands to read/set key parameters:
   - `X_RDKCENTRAL-COM_DeviceFingerPrint` (Enable, LoggingPeriod, LoggingLevel)
   - `X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing` (Enable, LookupTimeout)
   - `X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd` (Enable)
   - `X_RDKCENTRAL-COM_AdvancedParentalControl` (Enable)
   - `X_RDKCENTRAL-COM_PrivacyProtection` (Enable)
   - All RFC toggle parameters
4. **Security Agent Status Checks** — Commands to verify Security Agent process, socket connectivity, feature operational state
5. **WebConfig Diagnostics** — Commands to check blob version, trigger re-apply, verify WebConfig registration
6. **Feature Toggle Debugging** — Step-by-step commands to enable a feature via TR-181 and verify it takes effect end-to-end
7. **Script Execution and Debugging** — How to manually run `advsec.sh`, `start_adv_security.sh`, `advsec_cpu_mem_recovery.sh` with debug tracing
8. **Build and Test** — Build commands (`autogen.sh`, `configure`, `make`), unit test execution, test runner script
9. **Resource Monitoring** — Commands to monitor CPU and memory usage of security components
10. **Syscfg and PSM Inspection** — Commands to read persisted configuration values

## Style Guidelines

- All commands should be in fenced code blocks with `bash` syntax
- Group related commands under clear subheadings
- Include expected output patterns where helpful
- Match the concise, practical style of the Cellular Manager playbook
