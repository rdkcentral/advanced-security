---
description: "Generate TR-181 parameter-to-code ownership matrix for Advanced Security component modeled after Cellular Manager TR-181 matrix"
agent: "agent"
---

# Generate TR-181 Parameter Ownership Matrix

Generate a `docs/reference/tr181-matrix.md` for the **Advanced Security (CcspAdvSecurity)** component.

## Reference

Use the Cellular Manager TR-181 matrix as the structural template:
[tr181-matrix.md](../../../cellular/cellular-manager/docs/reference/tr181-matrix.md)

## Source Files to Analyze

- [cosa_adv_security_dml.c](../../source/AdvSecurityDml/cosa_adv_security_dml.c) — all DML Get/Set/Validate/Commit/Rollback handlers
- [cosa_adv_security_dml.h](../../source/AdvSecurityDml/cosa_adv_security_dml.h) — DML API declarations
- [cosa_adv_security_internal.c](../../source/AdvSecurityDml/cosa_adv_security_internal.c) — internal model CRUD
- [cosa_adv_security_internal.h](../../source/AdvSecurityDml/cosa_adv_security_internal.h) — data model structs
- [advsecurity_param.c](../../source/AdvSecurityDml/advsecurity_param.c) — feature param handling and start/stop
- [plugin_main.c](../../source/AdvSecurityDml/plugin_main.c) — DML function registration table
- [TR181-AdvSecurity.xml](../../config/TR181-AdvSecurity.xml) — XML data model definition

## Required Sections

1. **Scope** — What this matrix covers and why it's useful

2. **Ownership Matrix** — Table with columns: TR-181 Parameter | Primary Responsibility | Primary Files | Runtime Source | Notes
   Cover all parameter families:
   - `X_RDKCENTRAL-COM_DeviceFingerPrint.*` (Enable, LoggingPeriod, LoggingLevel)
   - `X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.*` (Enable, LookupTimeout, CustomURL)
   - `X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.*` (Enable)
   - `X_RDKCENTRAL-COM_AdvancedParentalControl.*` (Enable)
   - `X_RDKCENTRAL-COM_PrivacyProtection.*` (Enable)
   - `X_RDKCENTRAL-COM_RabidFramework.*` (MemoryLimit, MacCacheSize, DNSCacheSize)
   - All RFC toggle parameters (`*_RFC.Enable`)

3. **Ownership by Runtime Layer** — Table mapping layer → owned concerns → key files:
   - SSP Layer
   - DML Plugin Layer
   - Feature Control Layer (advsecurity_param)
   - WebConfig Layer
   - Shell Script Layer

4. **Frequently Needed Tracebacks** — Common investigation scenarios:
   - A: Why is DeviceFingerPrint not activating?
   - B: Why did a WebConfig blob get rejected?
   - C: Why is an RFC toggle not taking effect?
   - D: Why is SafeBrowsing lookup timing out?

5. **Change Management Guidance** — Steps to follow when modifying any TR-181 parameter behavior

## Style Guidelines

- Derive all mappings from actual source code analysis
- Use relative file links for all source references
- Match the Cellular Manager matrix format exactly
- Include the validate/commit/rollback chain for parameters that have it
