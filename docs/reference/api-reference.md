# Advanced Security Internal API Reference

This document describes the public internal API surface of the CcspAdvSecurity component.

Reference headers:
- `source/AdvSecurityDml/cosa_adv_security_internal.h`
- `source/AdvSecurityDml/cosa_adv_security_dml.h`
- `source/AdvSecurityDml/cosa_adv_security_webconfig.h`
- `source/AdvSecurityDml/advsecurity_helpers.h`
- `source/AdvSecurityDml/advsecurity_param.h`
- `source/AdvSecurityDml/cujoagent_dcl_api.h`

## 1. Return Conventions

- `ANSC_STATUS_SUCCESS` = `0` — Operation succeeded
- `ANSC_STATUS_FAILURE` = `1` — Operation failed
- DML handlers return `BOOL`: `TRUE` = handled, `FALSE` = unknown parameter
- `RETURN_OK` / `RETURN_ERROR` used in some utility paths

## 2. Core Types

### 2.1 Root Data Model: `COSA_DATAMODEL_AGENT`

The root struct aggregating all feature sub-models. Created by `CosaSecurityCreate()` and stored in global `g_pAdvSecAgent`.

| Field | Type | Purpose |
|-------|------|---------|
| `bEnable` | `BOOL` | DeviceFingerPrint master enable |
| `iStatus` | `int` | Component status |
| `iState` | `int` | Component state |
| `ulLoggingPeriod` | `ULONG` | Telemetry logging period (seconds) |
| `ulLogLevel` | `ULONG` | Agent log level |
| `pAdvSec` | `PCOSA_DATAMODEL_ADVSEC` | SafeBrowsing + Softflowd container |
| `pAdvPC` | `PCOSA_DATAMODEL_ADVPARENTALCONTROL` | Parental control |
| `pPrivProt` | `PCOSA_DATAMODEL_PRIVACYPROTECTION` | Privacy protection |
| `pRabid` | `PCOSA_DATAMODEL_RABID` | Rabid framework config |
| `pAdvPC_RFC` | `PCOSA_DATAMODEL_ADVPC_RFC` | Parental control RFC toggle |
| `pPrivProt_RFC` | `PCOSA_DATAMODEL_PRIVACYPROTECTION_RFC` | Privacy protection RFC toggle |
| `pDFIcmpv6_RFC` | `PCOSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC` | ICMPv6 fingerprinting RFC |
| `pWSDiscoveryAnalysis_RFC` | `PCOSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC` | WS-Discovery RFC |
| `pAdvSecOTM_RFC` | `PCOSA_DATAMODEL_ADVSECOTM_RFC` | OTM RFC |
| `pAdvSecUserSpace_RFC` | `PCOSA_DATAMODEL_ADVSECUSERSPACE_RFC` | UserSpace RFC |
| `pLevl_RFC` | `PCOSA_DATAMODEL_LEVL_RFC` | LEVL RFC |
| `pAdvSecAgent_RFC` | `PCOSA_DATAMODEL_ADVSECAGENT_RFC` | Agent RFC |
| `pAdvSecSafeBrowsing_RFC` | `PCOSA_DATAMODEL_ADVSECSAFEBROWSING_RFC` | SafeBrowsing RFC |
| `pAdvSecCujoTelemetryWiFiFP_RFC` | `PCOSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC` | WiFi FP telemetry RFC |
| `pAdvSecCujoTracer_RFC` | `PCOSA_DATAMODEL_ADVSECCUJOTRACER_RFC` | CujoTracer RFC |
| `pAdvSecCujoTelemetry_RFC` | `PCOSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC` | CujoTelemetry RFC |
| `pAdvSecSATE_RFC` | `PCOSA_DATAMODEL_ADVSECSATE_RFC` | SATE RFC |
| `pAdvSecTCPTrackerFilterDevices_RFC` | `PCOSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC` | TCP tracker RFC |
| `pAdvWifiDataCollection_RFC` | `PCOSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC` | WiFi data collection RFC |
| `pRaptr_RFC` | `PCOSA_DATAMODEL_RAPTR_RFC` | Raptr RFC |

### 2.2 Sub-Model Structs

| Struct | Key Fields |
|--------|-----------|
| `COSA_DATAMODEL_ADVSEC` | `pSafeBrows`, `pSoftFlowd` |
| `COSA_DATAMODEL_SB` | `bEnable`, `ulLookupTimeout` |
| `COSA_DATAMODEL_SOFTFLOWD` | `bEnable` |
| `COSA_DATAMODEL_ADVPARENTALCONTROL` | `bEnable` |
| `COSA_DATAMODEL_PRIVACYPROTECTION` | `bEnable` |
| `COSA_DATAMODEL_RABID` | `uMemoryLimit`, `uMacCacheSize`, `uDNSCacheSize` |
| All RFC structs (`*_RFC`) | `bEnable` |

### 2.3 Feature Enum

```c
typedef enum {
    ADVSEC_SAFEBROWSING,
    ADVSEC_SOFTFLOWD,
    ADVSEC_ALL
} advsec_feature_type;
```

### 2.4 Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `ADVSEC_MIN_LOG_TIMEOUT` | 60 (60 * 1 seconds) | Minimum logging period |
| `ADVSEC_MAX_LOG_TIMEOUT` | 2880 (60 * 48 seconds) | Maximum logging period |
| `ADVSEC_DEFAULT_LOG_TIMEOUT` | 1440 (60 * 24 seconds) | Default logging period |
| `ADVSEC_DEFAULT_LOOKUP_TIMEOUT` | 350 | Default (and minimum) SafeBrowsing lookup timeout |
| `ADVSEC_MAX_LOOKUP_TIMEOUT` | 6000 | Max SafeBrowsing lookup timeout |
| `MIN_AGENT_MEMORY_HARD_LIMIT` | 45 | Min Rabid memory limit (MB) |
| `MAX_RABID_MACCACHE_SIZE` | 32768 | Max MAC cache entries |
| `MAX_RABID_DNSCACHE_SIZE` | 32768 | Max DNS cache entries |

> **Note**: There is no `ADVSEC_MIN_LOOKUP_TIMEOUT` constant. The lower bound for `LookupTimeout` uses `ADVSEC_DEFAULT_LOOKUP_TIMEOUT` (350).

## 3. Lifecycle APIs

### 3.1 `CosaSecurityCreate()`

```c
ANSC_HANDLE CosaSecurityCreate(VOID);
```

Allocates the complete `COSA_DATAMODEL_AGENT` struct hierarchy including all feature and RFC sub-models. Initializes `syscfg`. Returns `ANSC_HANDLE` or `NULL` on allocation failure. Uses `goto mem_alloc_failure` pattern with `FreeCosaDmAgent()` cleanup.

### 3.2 `CosaSecurityInitialize(ANSC_HANDLE hThisObject)`

```c
ANSC_STATUS CosaSecurityInitialize(ANSC_HANDLE hThisObject);
```

Full component initialization:
1. Opens RBUS handle (`AdvSecurityEventConsumer`)
2. Initializes platform HAL DBs
3. Retrieves device info (model, firmware, HW, MAC)
4. Writes config params to `/tmp/advsec_config_params/`
5. Initializes WebConfig (`advsec_webconfig_init()`)
6. Loads all syscfg values into `g_pAdvSecAgent`
7. Sets default endpoint URL from partner config
8. Calls `CosaAdvSecInit()` if DeviceFingerPrint enabled
9. Starts logger thread and sysevent handler

### 3.3 `CosaSecurityRemove(ANSC_HANDLE hThisObject)`

```c
ANSC_STATUS CosaSecurityRemove(ANSC_HANDLE hThisObject);
```

Tears down all active features and frees memory via `FreeCosaDmAgent()`.

## 4. Feature Init/DeInit Pairs

All follow the pattern: persist to syscfg → check DeviceFingerPrint active → invoke shell script.

| Function | Feature | Script Flag |
|----------|---------|-------------|
| `CosaAdvSecInit()` / `CosaAdvSecDeInit()` | DeviceFingerPrint (core) | `-enable` / `-disable` |
| `CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING)` / `CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING)` | SafeBrowsing | `-start sb null` / `-stop sb null` |
| `CosaAdvSecStartFeatures(ADVSEC_SOFTFLOWD)` / `CosaAdvSecStopFeatures(ADVSEC_SOFTFLOWD)` | Softflowd | `-start null sf` / `-stop null sf` |
| `CosaStartAdvParentalControl()` / `CosaStopAdvParentalControl()` | Parental Control (feature) | `-startAdvPC` / `-stopAdvPC` |
| `CosaAdvPCInit()` / `CosaAdvPCDeInit()` | Parental Control (RFC toggle) | Calls Start/Stop above if feature active |
| `CosaStartPrivacyProtection()` / `CosaStopPrivacyProtection()` | Privacy Protection (feature) | `-startPrivProt` / `-stopPrivProt` |
| `CosaPrivacyProtectionInit()` / `CosaPrivacyProtectionDeInit()` | Privacy Protection (RFC toggle) | Calls Start/Stop above if feature active |
| `CosaAdvDFIcmpv6Init()` / `CosaAdvDFIcmpv6DeInit()` | ICMPv6 fingerprint | `-enableICMP6` / `-disableICMP6` |
| `CosaWSDisInit()` / `CosaWSDisDeInit()` | WS-Discovery | `-enableWSDiscovery` / `-disableWSDiscovery` |
| `CosaAdvSecOTMInit()` / `CosaAdvSecOTMDeInit()` | OTM | `-enableOTM` / `-disableOTM` |
| `CosaAdvSecUserSpaceInit()` | UserSpace (enable-only; DeInit commented out) | `-enableUS` |
| `CosaAdvSecAgentRaptrInit()` / `CosaAdvSecAgentRaptrDeInit()` | Raptr (enable-only via TR-181) | `-enableRaptr` / `-disableRaptr` |
| `CosaLevlInit()` / `CosaLevlDeInit()` | LEVL | `-enableLEVL` or `-enableLEVLwithUS` / `-disableLEVL` |
| `CosaAdvSecAgentInit()` / `CosaAdvSecAgentDeInit()` | Agent control | `-enableAGT` / `-disableAGT` |
| `CosaAdvSecSafeBrowsingInit()` / `...DeInit()` | SB RFC toggle | `-enableSBRule` / `-disableSBRule` |
| `CosaAdvSecCujoTelemetryWiFiFPInit()` / `...DeInit()` | WiFi FP telemetry | `-enableCTW` / `-disableCTW` |
| `CosaAdvSecCujoTracerInit()` / `...DeInit()` | CujoTracer | `-enableCT` / `-disableCT` |
| `CosaAdvSecCujoTelemetryInit()` / `...DeInit()` | CujoTelemetry | `-enableCTD` / `-disableCTD` |
| `CosaAdvSecSATEInit()` / `CosaAdvSecSATEDeInit()` | SATE | `-enableSATE` / `-disableSATE` |
| `CosaAdvSecTCPTrackerFilterDevicesInit()` / `...DeInit()` | TCP tracker filter | `-enableTCPTrackerFilterDevices` / `-disableTCPTrackerFilterDevices` |
| `CosaAdvWifiDataCollectionInit()` / `...DeInit()` | WiFi DCL | `-enableWifiDCL` / `-disableWifiDCL` |

## 5. Configuration APIs

| Function | Purpose |
|----------|---------|
| `CosaAdvSecGetLoggingPeriod()` | Read logging period from syscfg into model |
| `CosaAdvSecSetLoggingPeriod()` | Write logging period to syscfg, signal logger thread |
| `CosaAdvSecGetLogLevel()` | Read log level from syscfg into model |
| `CosaAdvSecSetLogLevel()` | Write log level to syscfg |
| `CosaAdvSecGetLookupTimeout()` | Read SafeBrowsing lookup timeout from syscfg |
| `CosaAdvSecSetLookupTimeout()` | Write lookup timeout to syscfg |
| `CosaAdvSecGetCustomURL()` | Read custom endpoint URL from syscfg |
| `CosaAdvSecSetCustomURL()` | Write custom endpoint URL (validated by `isValidUrl()`) |
| `CosaAdvSecStartFeatures(type)` | Start specific or all features |
| `CosaAdvSecStopFeatures(type)` | Stop specific or all features |
| `CosaRabidSetMemoryLimit(value)` | Set Rabid memory limit (min: 45 MB) |
| `CosaRabidSetMacCacheSize(value)` | Set Rabid MAC cache (max: 32768) |
| `CosaRabidSetDNSCacheSize(value)` | Set Rabid DNS cache (max: 32768) |
| `CosaAdvSecFetchSbConfig(param, ...)` | Fetch SafeBrowsing config from `/tmp/safebro.json` |
| `CosaAdvSecFlushConntrackTable()` | Flush connection tracking table via `conntrack -F` |

## 6. Syscfg Utility APIs

| Function | Purpose |
|----------|---------|
| `CosaGetSysCfgString(setting, pValue, pulSize)` | Read string from syscfg |
| `CosaSetSysCfgString(setting, pValue)` | Write string to syscfg + commit |
| `CosaGetSysCfgUlong(setting, pValue)` | Read unsigned long from syscfg |
| `CosaSetSysCfgUlong(setting, value)` | Write unsigned long to syscfg + commit |

## 7. DML Handler Catalog

### DeviceFingerPrint

| DML Function | Parameters Handled |
|-------------|-------------------|
| `DeviceFingerPrint_GetParamBoolValue` | `Enable` |
| `DeviceFingerPrint_SetParamBoolValue` | `Enable` |
| `DeviceFingerPrint_GetParamUlongValue` | `LoggingPeriod`, `LogLevel` |
| `DeviceFingerPrint_SetParamUlongValue` | `LoggingPeriod`, `LogLevel` |
| `DeviceFingerPrint_GetParamStringValue` | `EndpointURL` |
| `DeviceFingerPrint_SetParamStringValue` | `EndpointURL` |

### AdvancedSecurity (WebConfig Blob Ingestion)

| DML Function | Parameters Handled |
|-------------|-------------------|
| `AdvancedSecurity_SetParamStringValue` | `Data` (base64-encoded msgpack blob from WebConfig) |

### SafeBrowsing

| DML Function | Parameters Handled |
|-------------|-------------------|
| `SafeBrowsing_GetParamBoolValue` | `Enable` |
| `SafeBrowsing_SetParamBoolValue` | `Enable` |
| `SafeBrowsing_GetParamUlongValue` | `LookupTimeout`, `LookupTimeoutExceededCount`, `Threshold`, `Timeout`, `Cachettl`, `Ttl`, `WhitelistMaxEntries` |
| `SafeBrowsing_SetParamUlongValue` | `LookupTimeout` |
| `SafeBrowsing_GetParamStringValue` | `Endpoint`, `Blockpage`, `Warnpage`, `Cacheurl`, `OtmDedupFqdn` |
| `SafeBrowsing_Validate` | Pre-commit validation (currently NO-OP, always returns TRUE) |
| `SafeBrowsing_Commit` | Apply changes (currently NO-OP; actual logic is in SetParamBoolValue) |
| `SafeBrowsing_Rollback` | Restore on failure (currently NO-OP) |

### Softflowd

| DML Function | Parameters Handled |
|-------------|-------------------|
| `Softflowd_GetParamBoolValue` | `Enable` |
| `Softflowd_SetParamBoolValue` | `Enable` |
| `Softflowd_Validate` | Pre-commit validation |
| `Softflowd_Commit` | Apply enable/disable |
| `Softflowd_Rollback` | Restore on failure |

## 8. WebConfig APIs

| Function | Purpose |
|----------|---------|
| `advsec_webconfig_init()` | Register `advsecurity` subdoc with WebConfig framework |
| `advsec_webconfig_get_blobversion()` | Get current blob version |
| `advsec_webconfig_set_blobversion(version)` | Set blob version after successful apply |
| `advsec_webconfig_handle_blob(blob)` | Entry point for blob processing |
| `advsec_webconfig_process_request(doc)` | Apply parsed parameters to features |
| `advsec_webconfig_rollback()` | Revert to pre-blob state |
| `advsec_webconfig_free_resources()` | Cleanup allocated resources |

## 9. Msgpack Helper APIs

| Function | Purpose |
|----------|---------|
| `comp_helper_convert(buf, len, size, name, type, wrapper, process, destroy)` | Generic msgpack buffer decoder |
| `helper_convert_array(buf, len, ...)` | Array-based msgpack decoder |
| `advsecuritydoc_convert(buf, len)` | Decode WebConfig blob to `advsecuritydoc_t` |
| `advsecuritydoc_destroy(doc)` | Free `advsecuritydoc_t` and sub-allocations |
| `advsecuritydoc_strerror(errnum)` | Human-readable error string |

## 10. WiFi DCL APIs (Conditional: WIFI_DATA_COLLECTION)

| Function | Purpose |
|----------|---------|
| `cujoagent_wifidatacollection_init()` | Initialize WiFi data collection consumer |
| `cujoagent_wifidatacollection_deinit()` | Tear down WiFi data collection |
| `wifidcl_init_precheck()` | Validate WiFi webconfig init data readiness (retry loop) |
| `Wifi_GetParameterValue(param, returnVal)` | RBUS get for WiFi parameters |
| `Wifi_SetParameterValue(param, bValue)` | RBUS set for WiFi parameters |
| `Wifi_Get_Status(param)` | Check boolean status of WiFi parameter |

## 11. SSP APIs

| Function | Purpose |
|----------|---------|
| `ssp_create_advsec()` | Create CCSP component infrastructure |
| `ssp_engage_advsec()` | Register data model with CR, load plugin |
| `ssp_cancel_advsec()` | Cancel CPE controller, cleanup |
| `ssp_AdvsecMbi_MessageBusEngage(name, cfg, path)` | Connect to CCSP message bus |
| `drop_root()` | Check blocklist and manage root privileges |
| `isCujoBlocklisted()` | Read `/opt/secure/Blocklist_file.txt` for cujo-agent |

### Component Info Accessors

| Function | Returns |
|----------|---------|
| `ssp_AdvSecCCDmGetComponentName()` | Component name |
| `ssp_AdvSecCCDmGetComponentVersion()` | Component version |
| `ssp_AdvSecCCDmGetComponentAuthor()` | Component author |
| `ssp_AdvSecCCDmGetComponentHealth()` | Health status (Green/Yellow/Red) |
| `ssp_AdvSecCCDmGetComponentState()` | State (Running/Initializing) |
| `ssp_AdvSecCCDmGetLoggingEnabled()` | Logging flag |
| `ssp_AdvSecCCDmGetLoggingLevel()` | Current log level |
| `ssp_AdvSecCCDmSetLoggingLevel(level)` | Set log level |
| `ssp_AdvSecCCDmGetMemMaxUsage()` | Peak memory |
| `ssp_AdvSecCCDmGetMemMinUsage()` | Minimum memory |
| `ssp_AdvSecCCDmGetMemConsumed()` | Current memory |
