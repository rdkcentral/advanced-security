# TR-181 Parameter to Code Ownership Matrix

This matrix maps all `Device.DeviceInfo.X_RDKCENTRAL-COM_*` ownership areas to implementation files and runtime paths.

## Scope

- Covers all TR-181 parameters defined in `config/TR181-AdvSecurity.xml`
- Maps each parameter family to the DML handler, internal API, syscfg key, and shell script path
- Supports faster triage, safer refactoring, and clearer reviewer ownership

## Ownership Matrix

### Core Feature Parameters

| TR-181 Parameter | Primary Responsibility | DML Handler | Internal API | syscfg Key | Script Flag |
|-----------------|----------------------|-------------|--------------|------------|-------------|
| `X_RDKCENTRAL-COM_DeviceFingerPrint.Enable` | Core feature enable/disable | `DeviceFingerPrint_SetParamBoolValue` | `CosaAdvSecInit()` / `CosaAdvSecDeInit()` | `Advsecurity_DeviceFingerPrint` | `-enable` / `-disable` |
| `X_RDKCENTRAL-COM_DeviceFingerPrint.LoggingPeriod` | Telemetry logging interval (seconds) | `DeviceFingerPrint_SetParamUlongValue` | `CosaAdvSecSetLoggingPeriod()` | `Advsecurity_LoggingPeriod` | — |
| `X_RDKCENTRAL-COM_DeviceFingerPrint.EndpointURL` | Cloud endpoint URL (HTTPS only) | `DeviceFingerPrint_SetParamStringValue` | URL validated by `isValidUrl()` | `Advsecurity_CustomEndpointURL` | — |
| `X_RDKCENTRAL-COM_DeviceFingerPrint.LogLevel` | Agent log level | `DeviceFingerPrint_SetParamUlongValue` | `CosaAdvSecSetLogLevel()` | `Advsecurity_LogLevel` | — |
| `X_RDKCENTRAL-COM_DeviceFingerPrint.FlushConntrackTable` | Trigger to flush connection tracking table (always reads FALSE) | `DeviceFingerPrint_SetParamBoolValue` | `CosaAdvSecFlushConntrackTable()` | — (trigger, no persistence) | — |

### AdvancedSecurity.SafeBrowsing Parameters

| TR-181 Parameter | Primary Responsibility | DML Handler | Internal API | syscfg Key | Script Flag |
|-----------------|----------------------|-------------|--------------|------------|-------------|
| `SafeBrowsing.Enable` | Safe browsing on/off | `SafeBrowsing_SetParamBoolValue` | `CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING)` / `CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING)` | `Advsecurity_SafeBrowsing` | `-start sb null` / `-stop sb null` |
| `SafeBrowsing.LookupTimeout` | DNS lookup timeout (ms) | `SafeBrowsing_SetParamUlongValue` | `CosaAdvSecSetLookupTimeout()` | `Advsecurity_LookupTimeout` | `-lookupTimeout` |
| `SafeBrowsing.LookupTimeoutExceededCount` | Read-only counter | `SafeBrowsing_GetParamUlongValue` | Read from `/tmp/advsec_lkup_exceed_cnt` | — | — |
| `SafeBrowsing.Threshold` | Read-only config | `SafeBrowsing_GetParamUlongValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Timeout` | Read-only config | `SafeBrowsing_GetParamUlongValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Cachettl` | Read-only config | `SafeBrowsing_GetParamUlongValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Ttl` | Read-only config | `SafeBrowsing_GetParamUlongValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.WhitelistMaxEntries` | Read-only config | `SafeBrowsing_GetParamUlongValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Endpoint` | Read-only config string | `SafeBrowsing_GetParamStringValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Blockpage` | Read-only config string | `SafeBrowsing_GetParamStringValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Warnpage` | Read-only config string | `SafeBrowsing_GetParamStringValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.Cacheurl` | Read-only config string | `SafeBrowsing_GetParamStringValue` | `CosaAdvSecFetchSbConfig()` | — | — |
| `SafeBrowsing.OtmDedupFqdn` | Read-only config string | `SafeBrowsing_GetParamStringValue` | `CosaAdvSecFetchSbConfig()` | — | — |

### AdvancedSecurity.Softflowd Parameters

| TR-181 Parameter | DML Handler | Internal API | syscfg Key | Script Flag |
|-----------------|-------------|--------------|------------|-------------|
| `Softflowd.Enable` | `Softflowd_SetParamBoolValue` | `CosaAdvSecStartFeatures(ADVSEC_SOFTFLOWD)` / `CosaAdvSecStopFeatures(ADVSEC_SOFTFLOWD)` | `Advsecurity_Softflowd` | `-start null sf` / `-stop null sf` |

### AdvancedParentalControl Parameters

| TR-181 Parameter | DML Handler | Internal API | syscfg Key | Script Flag |
|-----------------|-------------|--------------|------------|-------------|
| `X_RDKCENTRAL-COM_AdvancedParentalControl.Activate` | `AdvancedParentalControl_SetParamBoolValue` | `CosaStartAdvParentalControl()` / `CosaStopAdvParentalControl()` | `Adv_PCActivate` | `-startAdvPC` / `-stopAdvPC` |

### PrivacyProtection Parameters

| TR-181 Parameter | DML Handler | Internal API | syscfg Key | Script Flag |
|-----------------|-------------|--------------|------------|-------------|
| `X_RDKCENTRAL-COM_PrivacyProtection.Activate` | `PrivacyProtection_SetParamBoolValue` | `CosaStartPrivacyProtection()` / `CosaStopPrivacyProtection()` | `Adv_PPActivate` | `-startPrivProt` / `-stopPrivProt` |

### RabidFramework Parameters

| TR-181 Parameter | DML Handler | Internal API | syscfg Key | Bounds |
|-----------------|-------------|--------------|------------|--------|
| `RFC.Feature.RabidFramework.MemoryLimit` | `RabidFramework_SetParamUlongValue` | `CosaRabidSetMemoryLimit()` | `Advsecurity_RabidMemoryLimit` | min: 45 MB |
| `RFC.Feature.RabidFramework.MacCacheSize` | `RabidFramework_SetParamUlongValue` | `CosaRabidSetMacCacheSize()` | `Advsecurity_RabidMacCacheSize` | max: 32768 |
| `RFC.Feature.RabidFramework.DNSCacheSize` | `RabidFramework_SetParamUlongValue` | `CosaRabidSetDNSCacheSize()` | `Advsecurity_RabidDNSCacheSize` | max: 32768 |

### RFC Feature Toggle Parameters

| TR-181 Object | DML Get Handler | DML Set Handler | Init Function | DeInit Function | syscfg Key |
|--------------|-----------------|-----------------|---------------|-----------------|------------|
| `Feature.AdvancedParentalControl` | `AdvancedParentalControl_RFC_GetParamBoolValue` | `AdvancedParentalControl_RFC_SetParamBoolValue` | `CosaAdvPCInit()` | `CosaAdvPCDeInit()` | `Adv_PCRFCEnable` |
| `Feature.PrivacyProtection` | `PrivacyProtection_RFC_GetParamBoolValue` | `PrivacyProtection_RFC_SetParamBoolValue` | `CosaPrivacyProtectionInit()` | `CosaPrivacyProtectionDeInit()` | `Adv_PrivProtRFCEnable` |
| `Feature.DeviceFingerPrintICMPv6` | `DeviceFingerPrintICMPv6_RFC_GetParamBoolValue` | `DeviceFingerPrintICMPv6_RFC_SetParamBoolValue` | `CosaAdvDFIcmpv6Init()` | `CosaAdvDFIcmpv6DeInit()` | `Adv_DFICMPv6RFCEnable` |
| `Feature.WS-Discovery_Analysis` | `WS_Discovery_Analysis_RFC_GetParamBoolValue` | `WS_Discovery_Analysis_RFC_SetParamBoolValue` | `CosaWSDisInit()` | `CosaWSDisDeInit()` | `Adv_WSDisAnaRFCEnable` |
| `Feature.AdvancedSecurityOTM` | `AdvancedSecurityOTM_RFC_GetParamBoolValue` | `AdvancedSecurityOTM_RFC_SetParamBoolValue` | `CosaAdvSecOTMInit()` | `CosaAdvSecOTMDeInit()` | `Adv_AdvSecOTMRFCEnable` |
| `Feature.AdvanceSecurityUserSpace` | `AdvanceSecurityUserSpace_RFC_GetParamBoolValue` | `AdvanceSecurityUserSpace_RFC_SetParamBoolValue` | `CosaAdvSecUserSpaceInit()` | — (DeInit commented out; cannot be disabled via TR-181) | `Adv_AdvSecUserSpaceRFCEnable` |
| `Feature.AdvSecAgentRaptr` | `AdvSecAgentRaptr_RFC_GetParamBoolValue` | `AdvSecAgentRaptr_RFC_SetParamBoolValue` | `CosaAdvSecAgentRaptrInit()` | `CosaAdvSecAgentRaptrDeInit()` (enable-only via TR-181) | `Adv_RaptrRFCEnable` |
| `Feature.AdvanceSecurityCujoTracer` | `AdvanceSecurityCujoTracer_RFC_GetParamBoolValue` | `AdvanceSecurityCujoTracer_RFC_SetParamBoolValue` | `CosaAdvSecCujoTracerInit()` | `CosaAdvSecCujoTracerDeInit()` | `Adv_AdvSecCujoTracerRFCEnable` |
| `Feature.AdvanceSecurityCujoTelemetry` | `AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue` | `AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue` | `CosaAdvSecCujoTelemetryInit()` | `CosaAdvSecCujoTelemetryDeInit()` | `Adv_AdvSecCujoTelemetryRFCEnable` |
| `Feature.AdvSecSentryAtTheEdge` | `AdvSecSentryAtTheEdge_RFC_GetParamBoolValue` | `AdvSecSentryAtTheEdge_RFC_SetParamBoolValue` | `CosaAdvSecSATEInit()` | `CosaAdvSecSATEDeInit()` | `Adv_SATERFCEnable` |
| `Feature.AdvSecTCPTrackerFilterDevices` | `AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue` | `AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue` | `CosaAdvSecTCPTrackerFilterDevicesInit()` | `CosaAdvSecTCPTrackerFilterDevicesDeInit()` | `Adv_TCPTrackerFilterDevicesRFCEnable` |

### Conditional Parameters (WIFI_DATA_COLLECTION build flag)

| TR-181 Object | DML Handlers | Init/DeInit | syscfg Key |
|--------------|-------------|-------------|------------|
| `Feature.WifiDataCollection` | `WifiDataCollection_RFC_Get/SetParamBoolValue` | `CosaAdvWifiDataCollectionInit()` / `CosaAdvWifiDataCollectionDeInit()` | `Adv_WifiDataCollectionRFCEnable` |
| `Feature.Levl` | `Levl_RFC_Get/SetParamBoolValue` | `CosaLevlInit()` / `CosaLevlDeInit()` | `Adv_LevlRFCEnable` |
| `Feature.AdvSecAgent` | `AdvSecAgent_RFC_Get/SetParamBoolValue` | `CosaAdvSecAgentInit()` / `CosaAdvSecAgentDeInit()` | `Adv_AdvSecAgentRFCEnable` |
| `Feature.AdvSecSafeBrowsing` | `AdvSecSafeBrowsing_RFC_Get/SetParamBoolValue` | `CosaAdvSecSafeBrowsingInit()` / `CosaAdvSecSafeBrowsingDeInit()` | `Adv_AdvSecSafeBrowsingRFCEnable` |
| `Feature.AdvSecCujoTelemetryWiFiFP` | `AdvSecCujoTelemetryWiFiFP_RFC_Get/SetParamBoolValue` | `CosaAdvSecCujoTelemetryWiFiFPInit()` / `CosaAdvSecCujoTelemetryWiFiFPDeInit()` | `Adv_AdvSecCujoTelemetryWiFiFPRFCEnable` |

## Ownership by Runtime Layer

| Layer | Owns | Key Files |
|-------|------|-----------|
| SSP Layer | Process lifecycle, privilege management, bus connection | `source/AdvSecuritySsp/ssp_main.c`, `ssp_action.c` |
| DML Plugin Layer | TR-181 function registration, plugin load/unload | `source/AdvSecurityDml/plugin_main.c` |
| DML Handler Layer | Parameter validation, get/set dispatching | `source/AdvSecurityDml/cosa_adv_security_dml.c` |
| Internal Data Model Layer | Feature lifecycle, syscfg persistence, device info, sysevent | `source/AdvSecurityDml/cosa_adv_security_internal.c` |
| WebConfig Layer | Blob decode, apply, version management, rollback | `source/AdvSecurityDml/cosa_adv_security_webconfig.c`, `advsecurity_param.c` |
| Shell Script Layer | Agent control, kernel modules, iptables, feature flags | `scripts/advsec.sh`, `scripts/start_adv_security.sh` |
| WiFi DCL Layer | Data collection, RBUS events, socket I/O | `source/AdvSecurityDml/cujoagent_dcl_api.c` |

## Frequently Needed Tracebacks

### A. Why is DeviceFingerPrint not activating?

1. Check `CosaSecurityInitialize()` in `cosa_adv_security_internal.c` — does it call `CosaAdvSecInit()`?
2. Verify syscfg value for `Advsecurity_DeviceFingerPrint` is 1
3. Check if `start_adv_security.sh -enable` executed successfully (exit code)
4. Verify agent binary exists on filesystem
5. Check bridge mode is not active

### B. Why did a WebConfig blob get rejected?

1. Check blob version vs current in `advsec_webconfig_get_blobversion()`
2. Check `advsecuritydoc_convert()` for msgpack decode errors
3. Check `process_advsecurityparams()` for missing required fields
4. Check `advsec_webconfig_process_request()` for feature apply failures
5. Check if rollback was triggered

### C. Why is an RFC toggle not taking effect?

1. Verify DML set handler was called (check `CcspTraceWarning` output)
2. Verify syscfg value persisted (e.g., `syscfg get Adv_PCRFCEnable`)
3. Check if DeviceFingerPrint is enabled (prerequisite for shell invocation)
4. Check if `Is_Agent_Initialization_Completed()` returns true
5. Verify `start_adv_security.sh` flag is correct for the feature

### D. Why is SafeBrowsing lookup timing out?

1. Check `LookupTimeout` value in syscfg: `Advsecurity_LookupTimeout`
2. Check `LookupTimeoutExceededCount` at `/tmp/advsec_lkup_exceed_cnt`
3. Verify endpoint URL is reachable: check `Advsecurity_CustomEndpointURL`
4. Check `/tmp/safebro.json` for agent-side configuration
5. Verify DNS resolution working on device

## Change Management Guidance

When changing any TR-181 parameter behavior:

1. Update this matrix with file-level ownership changes.
2. Update `docs/reference/` and troubleshooting references where affected.
3. Add or update unit tests in `source/test/CcspAdvSecurityDmlTest/`.
4. Verify WebConfig integration if parameter is blob-settable.
5. Validate syscfg persistence round-trip.
6. Test with DeviceFingerPrint both enabled and disabled.
