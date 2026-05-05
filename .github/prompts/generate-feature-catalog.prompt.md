---
description: "Generate RFC feature catalog and WebConfig integration reference for Advanced Security component modeled after Cellular Manager callbacks doc"
agent: "agent"
---

# Generate Feature Catalog Reference

Generate a `docs/reference/feature-catalog.md` for the **Advanced Security (CcspAdvSecurity)** component documenting all feature modules, their RFC toggles, and WebConfig integration.

## Reference

Use the Cellular Manager callback catalog as the structural template for structure and depth:
[callbacks.md](../../../cellular/cellular-manager/docs/reference/callbacks.md)

## Source Files to Analyze

- [cosa_adv_security_internal.h](../../source/AdvSecurityDml/cosa_adv_security_internal.h) — feature enum, RFC structs, init/deinit declarations
- [cosa_adv_security_internal.c](../../source/AdvSecurityDml/cosa_adv_security_internal.c) — feature initialization implementations
- [advsecurity_param.c](../../source/AdvSecurityDml/advsecurity_param.c) — feature start/stop, RFC handling
- [advsecurity_param.h](../../source/AdvSecurityDml/advsecurity_param.h) — param API declarations
- [cosa_adv_security_dml.c](../../source/AdvSecurityDml/cosa_adv_security_dml.c) — DML handlers
- [cosa_adv_security_webconfig.c](../../source/AdvSecurityDml/cosa_adv_security_webconfig.c) — WebConfig blob handling
- [plugin_main.c](../../source/AdvSecurityDml/plugin_main.c) — registration table
- [scripts/advsec.sh](../../scripts/advsec.sh) — shell-level feature control

## Required Sections

1. **Why This Exists** — Feature interaction complexity, RFC dependencies, troubleshooting aid

2. **Feature Families** — List all feature families:
   - Core Features (DeviceFingerPrint, SafeBrowsing, Softflowd)
   - Security Policies (AdvancedParentalControl, PrivacyProtection)
   - Framework (RabidFramework)
   - WiFi Data Collection (DCL/LEVL)
   - RFC Feature Toggles

3. **Per-Feature Documentation** — For each feature family, document:

   ### DeviceFingerPrint
   - TR-181 parameter: `X_RDKCENTRAL-COM_DeviceFingerPrint`
   - Enable/disable flow with Mermaid sequence diagram
   - Init/deinit functions
   - Persistence mechanism (syscfg key)
   - Related RFC toggles (ICMPv6, WS-Discovery)
   - Side effects and dependencies
   - Failure signatures

   ### SafeBrowsing
   - TR-181 parameter: `X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing`
   - Lookup timeout configuration
   - Custom URL support
   - Validate/Commit/Rollback cycle
   - RFC toggle: `AdvSecSafeBrowsing_RFC`

   ### Softflowd
   - TR-181 parameter: `X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd`
   - Enable/disable flow
   - Validate/Commit/Rollback cycle

   ### AdvancedParentalControl
   - TR-181 parameter and RFC toggle
   - Enable/disable flow

   ### PrivacyProtection
   - TR-181 parameter and RFC toggle
   - Enable/disable flow

   ### RabidFramework
   - Configuration parameters (MemoryLimit, MacCacheSize, DNSCacheSize)
   - Set API flow

4. **RFC Toggle Master Table** — Complete table with columns:
   - RFC Parameter Name | TR-181 Path | Init Function | DeInit Function | Controlled Feature | Persistence Key

5. **WebConfig Integration** — Document the full blob lifecycle:
   - Registration and subdoc name
   - Blob version management
   - Decode → process → commit/rollback sequence diagram
   - Error handling and retry behavior
   - Rollback scenarios

6. **Feature Interaction Matrix** — Which features depend on or conflict with others

7. **Edge Cases** — Document known edge cases:
   - Feature enabled via TR-181 but RFC disabled
   - Multiple features competing for resources
   - WebConfig overriding manual TR-181 settings

## Style Guidelines

- Use Mermaid sequence diagrams for each feature enable/disable flow
- Include actual init/deinit function names from source
- Document failure signatures for each feature
- Cross-reference troubleshooting doc for decision trees
