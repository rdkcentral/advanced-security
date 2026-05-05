---
description: "Generate onboarding guide for Advanced Security component modeled after Cellular Manager onboarding doc"
agent: "agent"
---

# Generate Onboarding Guide

Generate a `docs/onboarding.md` for the **Advanced Security (CcspAdvSecurity)** component — a "First 30 Minutes" guide for new engineers.

## Reference

Use the Cellular Manager onboarding doc as the structural template:
[onboarding.md](../../../cellular/cellular-manager/docs/onboarding.md)

## Source Files for Context

- [README.md](../../README.md) — component overview
- All source under [source/AdvSecurityDml/](../../source/AdvSecurityDml/) and [source/AdvSecuritySsp/](../../source/AdvSecuritySsp/)
- [scripts/](../../scripts/) — operational scripts
- [config/TR181-AdvSecurity.xml](../../config/TR181-AdvSecurity.xml) — data model
- [source/test/](../../source/test/) — unit tests

## Required Sections

1. **Outcome** — By end of 30 minutes, engineer should be able to:
   - Explain the plugin-based architecture and feature modules
   - Map source files to responsibilities (SSP, DML, WebConfig, scripts)
   - Run first-line diagnostics for security feature issues
   - Triage a feature activation or WebConfig failure with evidence

2. **Minute 0-5: Build the Mental Model** — Reading order for docs (architecture → workflows → developer playbook), key concepts: SSP bootstrap, COSA plugin, feature modules, RFC toggles, Security Agent relationship

3. **Minute 5-10: Map Files to Responsibilities** — Table mapping responsibility → file:
   - Daemon bootstrap → `ssp_main.c`
   - Component registration → `ssp_action.c`
   - Plugin entry/DML registration → `plugin_main.c`
   - Feature data model → `cosa_adv_security_internal.c/h`
   - TR-181 handlers → `cosa_adv_security_dml.c/h`
   - WebConfig integration → `cosa_adv_security_webconfig.c/h`
   - Feature control logic → `advsecurity_param.c/h`
   - Shell operations → `scripts/advsec.sh`

4. **Minute 10-15: Learn Critical Log Signatures** — Must-recognize log patterns for component startup, feature enable/disable, WebConfig processing, errors

5. **Minute 15-20: Run First-Line Diagnostics** — Shell commands to verify process, check TR-181 params, verify Security Agent, check feature states

6. **Minute 20-25: Validate Feature Activation** — Step-by-step: enable a feature via `dmcli`, verify TR-181 value persisted, check Security Agent responded, confirm feature operational

7. **Minute 25-30: Complete One Triage Drill** — Scenario: feature fails to activate. Capture logs, identify failure point, map to source code, write hypothesis. Link to troubleshooting doc.

8. **What Good Looks Like** — Criteria for a good first triage note (timeline, evidence, hypothesis, confidence, next step)

## Style Guidelines

- Keep the 30-minute time-boxed structure
- Use tables for file-to-responsibility mapping
- Include actual shell commands, not pseudocode
- Link to other docs (architecture, troubleshooting, playbook) that will be generated
