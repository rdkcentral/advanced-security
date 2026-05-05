---
description: "Generate internal API reference for Advanced Security component modeled after Cellular Manager HAL API reference"
agent: "agent"
---

# Generate Internal API Reference

Generate a `docs/reference/api-reference.md` for the **Advanced Security (CcspAdvSecurity)** component documenting all public internal APIs.

## Reference

Use the Cellular Manager HAL API reference as the structural template:
[hal-api.md](../../../cellular/cellular-manager/docs/reference/hal-api.md)

## Source Files to Analyze

Read these headers and implementation files to extract all API signatures:

- [cosa_adv_security_internal.h](../../source/AdvSecurityDml/cosa_adv_security_internal.h) — lifecycle APIs, feature init/deinit pairs, config get/set
- [cosa_adv_security_internal.c](../../source/AdvSecurityDml/cosa_adv_security_internal.c) — implementations
- [cosa_adv_security_dml.h](../../source/AdvSecurityDml/cosa_adv_security_dml.h) — DML API declarations
- [cosa_adv_security_dml.c](../../source/AdvSecurityDml/cosa_adv_security_dml.c) — DML implementations
- [advsecurity_param.h](../../source/AdvSecurityDml/advsecurity_param.h) — parameter handling APIs
- [advsecurity_param.c](../../source/AdvSecurityDml/advsecurity_param.c) — implementations
- [advsecurity_helpers.h](../../source/AdvSecurityDml/advsecurity_helpers.h) — msgpack helper APIs
- [cosa_adv_security_webconfig.h](../../source/AdvSecurityDml/cosa_adv_security_webconfig.h) — WebConfig APIs
- [cujoagent_dcl_api.h](../../source/AdvSecurityDml/cujoagent_dcl_api.h) — WiFi DCL APIs
- [plugin_main.h](../../source/AdvSecurityDml/plugin_main.h) — plugin entry points
- [ssp_action.c](../../source/AdvSecuritySsp/ssp_action.c) — SSP APIs

## Required Sections

1. **Return Conventions** — Standard return values and error codes used across APIs

2. **Core Types** — Document all key data structures:
   - `COSA_DATAMODEL_AGENT` (root model struct)
   - `COSA_DATAMODEL_ADVSEC` (SafeBrowsing + Softflowd)
   - `COSA_DATAMODEL_SB` (SafeBrowsing with LookupTimeout)
   - `COSA_DATAMODEL_SOFTFLOWD`
   - `COSA_DATAMODEL_ADVPARENTALCONTROL`
   - `COSA_DATAMODEL_PRIVACYPROTECTION`
   - `COSA_DATAMODEL_RABID`
   - All RFC structs
   - `advsec_feature_type` enum

3. **Lifecycle APIs** — Document each with signature, behavior, and usage context:
   - `CosaSecurityCreate()` / `CosaSecurityInitialize()` / `CosaSecurityRemove()`

4. **Feature Init/DeInit APIs** — Table of all feature init/deinit function pairs with their RFC parameter and controlled behavior

5. **Configuration APIs** — Document get/set pairs:
   - `CosaAdvSecGetLoggingPeriod()` / `CosaAdvSecSetLoggingPeriod()`
   - `CosaAdvSecGetLogLevel()` / `CosaAdvSecSetLogLevel()`
   - `CosaAdvSecGetLookupTimeout()` / `CosaAdvSecSetLookupTimeout()`
   - `CosaAdvSecGetCustomURL()` / `CosaAdvSecSetCustomURL()`
   - `CosaAdvSecStartFeatures()` / `CosaAdvSecStopFeatures()`
   - `CosaRabidSet*` functions

6. **DML API Catalog** — Table mapping TR-181 object → DML functions (GetBool, SetBool, GetUlong, SetUlong, GetString, SetString, Validate, Commit, Rollback)

7. **WebConfig APIs** — Document blob handling lifecycle:
   - `advsec_webconfig_init()` → `advsec_webconfig_handle_blob()` → `advsec_webconfig_process_request()` → `advsec_webconfig_rollback()` → `advsec_webconfig_free_resources()`

8. **Helper APIs** — `comp_helper_convert()`, `helper_convert_array()` — msgpack decoding utilities

9. **WiFi DCL APIs** — `cujoagent_wifidatacollection_init()` / `cujoagent_wifidatacollection_deinit()` (conditional on `WIFI_DATA_COLLECTION`)

10. **SSP APIs** — `ssp_create_advsec()`, `ssp_engage_advsec()`, `ssp_cancel_advsec()`, component info accessors

## Style Guidelines

- Document each API with: signature, purpose, parameters, return value, usage context
- Group by functional area (lifecycle, config, DML, webconfig, helpers)
- Use tables for bulk API catalogs
- Derive all signatures from actual source code
