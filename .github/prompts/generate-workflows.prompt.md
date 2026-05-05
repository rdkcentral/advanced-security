---
description: "Generate functional workflows documentation for Advanced Security component modeled after Cellular Manager workflows doc"
agent: "agent"
---

# Generate Workflows Documentation

Generate a comprehensive `docs/workflows.md` for the **Advanced Security (CcspAdvSecurity)** component documenting implemented runtime workflows.

## Reference

Use the Cellular Manager workflows doc as the structural template:
[workflows.md](../../../cellular/cellular-manager/docs/workflows.md)

## Source Files to Analyze

Read these source files to extract accurate workflow details:

- [cosa_adv_security_internal.c](../../source/AdvSecurityDml/cosa_adv_security_internal.c) — CosaSecurityCreate/Initialize/Remove lifecycle
- [cosa_adv_security_dml.c](../../source/AdvSecurityDml/cosa_adv_security_dml.c) — DML get/set/validate/commit/rollback handlers
- [cosa_adv_security_webconfig.c](../../source/AdvSecurityDml/cosa_adv_security_webconfig.c) — WebConfig blob processing workflow
- [advsecurity_param.c](../../source/AdvSecurityDml/advsecurity_param.c) — feature start/stop, RFC init/deinit
- [advsecurity_helpers.c](../../source/AdvSecurityDml/advsecurity_helpers.c) — msgpack processing
- [ssp_action.c](../../source/AdvSecuritySsp/ssp_action.c) — component engage/cancel
- [plugin_main.c](../../source/AdvSecurityDml/plugin_main.c) — plugin load/unload
- Shell scripts:
  - [advsec.sh](../../scripts/advsec.sh)
  - [start_adv_security.sh](../../scripts/start_adv_security.sh)
  - [advsec_cpu_mem_recovery.sh](../../scripts/advsec_cpu_mem_recovery.sh)
  - [advsec_log_fp_status.sh](../../scripts/advsec_log_fp_status.sh)

## Required Sections

1. **Component Startup Workflow** — Mermaid sequence diagram: main → drop_root → daemonize → message bus → ssp_create → ssp_engage → plugin load → CosaSecurityCreate → CosaSecurityInitialize → feature init
2. **Feature Enable/Disable Workflow** — How a TR-181 set on a feature boolean (e.g., DeviceFingerPrint.Enable) flows through DML → internal APIs → shell script invocation → Security Agent control
3. **RFC Feature Toggle Workflow** — How RFC flags are read, how init/deinit pairs are called, syscfg persistence
4. **SafeBrowsing Workflow** — Enable/disable flow, lookup timeout configuration, custom URL handling, validate/commit/rollback cycle
5. **WebConfig Blob Processing Workflow** — Mermaid diagram: blob receive → version check → msgpack decode → apply settings → commit/rollback → version update
6. **Parental Control and Privacy Protection Workflow** — Enable/disable flow and RFC interaction
7. **Softflowd Workflow** — Network flow monitoring enable/disable
8. **WiFi Data Collection Workflow** — DCL consumer init, socket communication, CSI data flow (when `WIFI_DATA_COLLECTION` enabled)
9. **CPU/Memory Recovery Workflow** — How `advsec_cpu_mem_recovery.sh` monitors and recovers from resource exhaustion
10. **Component Shutdown Workflow** — CosaSecurityRemove → feature deinit → bus cleanup

## Style Guidelines

- Use Mermaid sequence diagrams for each major workflow
- Document key conditions and decision points
- Include code path references as relative file links
- List failure signatures and edge cases for each workflow
- Match depth and format of the Cellular Manager workflows doc
