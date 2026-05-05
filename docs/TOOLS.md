# CcspAdvSecurity — Tools Reference

Complete catalog of every function, script, and API in the CcspAdvSecurity component. Organized by source file with inputs, outputs, and purpose.

---

## 1. DML Handlers (`cosa_adv_security_dml.c`)

TR-181 Data Model Layer functions registered via `COSA_Init` in `plugin_main.c`. Each object exposes Get/Set handlers called by the CCSP message bus.

### 1.1 Input Validation

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `isValidUrl(char *inputparam)` | URL string | `ANSC_STATUS` (SUCCESS = valid) | Rejects non-HTTPS URLs and command injection characters (`;`, `&`, `\|`, `'`) |

### 1.2 DeviceFingerPrint Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `DeviceFingerPrint_GetParamBoolValue` | `ParamName`, `*pBool` | `TRUE` on match | L119 |
| `DeviceFingerPrint_SetParamBoolValue` | `ParamName`, `bValue` | `TRUE` on success | L179 |
| `DeviceFingerPrint_GetParamUlongValue` | `ParamName`, `*pUlong` | `TRUE` on match | L250 |
| `DeviceFingerPrint_SetParamUlongValue` | `ParamName`, `uValue` | `TRUE` on success | L324 |
| `DeviceFingerPrint_GetParamStringValue` | `ParamName`, `pValue`, `*pUlSize` | `ULONG` (0=success) | L440 |
| `DeviceFingerPrint_SetParamStringValue` | `ParamName`, `pString` | `TRUE` on success | L507 |

**Parameters**: `Enable`, `LoggingPeriod`, `LookupTimeout`, `SBConfig` (URL), `CustomEndpointURL`, `DefaultEndpointURL`, `SbConfigStatus`, `SbReputationConfig`

### 1.3 AdvancedSecurity Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `AdvancedSecurity_SetParamStringValue` | `ParamName`, `pString` | `TRUE` on success | L575 |

**Parameters**: `ConfigURL` — passes through `isValidUrl()` validation, triggers webconfig blob processing

### 1.4 SafeBrowsing Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `SafeBrowsing_GetParamBoolValue` | `ParamName`, `*pBool` | `TRUE` on match | L760 |
| `SafeBrowsing_SetParamBoolValue` | `ParamName`, `bValue` | `TRUE` on success | L825 |
| `SafeBrowsing_GetParamUlongValue` | `ParamName`, `*pUlong` | `TRUE` on match | L1106 |
| `SafeBrowsing_SetParamUlongValue` | `ParamName`, `uValue` | `TRUE` on success | L1019 |
| `SafeBrowsing_GetParamStringValue` | `ParamName`, `pValue`, `*pUlSize` | `ULONG` | L1188 |

**Note**: SafeBrowsing `Validate`, `Commit`, `Rollback` are **no-ops** — state changes happen directly in `SetParamBoolValue`.

### 1.5 Softflowd Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `Softflowd_GetParamBoolValue` | `ParamName`, `*pBool` | `TRUE` on match | L1310 |
| `Softflowd_SetParamBoolValue` | `ParamName`, `bValue` | `TRUE` on success | L1377 |

**Note**: Validate/Commit/Rollback are also **no-ops**.

### 1.6 AdvancedParentalControl Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `AdvancedParentalControl_GetParamBoolValue` | `ParamName`, `*pBool` | `TRUE` on match | L1577 |
| `AdvancedParentalControl_SetParamBoolValue` | `ParamName`, `bValue` | `TRUE` on success | L1642 |

### 1.7 PrivacyProtection Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `PrivacyProtection_GetParamBoolValue` | `ParamName`, `*pBool` | `TRUE` on match | L1840 |
| `PrivacyProtection_SetParamBoolValue` | `ParamName`, `bValue` | `TRUE` on success | L1905 |

### 1.8 RabidFramework Object

| Function | Inputs | Output | Source Line |
|----------|--------|--------|-------------|
| `RabidFramework_GetParamUlongValue` | `ParamName`, `*pUlong` | `TRUE` on match | L2100 |
| `RabidFramework_SetParamUlongValue` | `ParamName`, `uValue` | `TRUE` on success | L2162 |

**Parameters**: `MemoryLimit` (≥ 45 MB), `MacCacheSize` (≤ 32768), `DnsCacheSize` (≤ 32768)

### 1.9 RFC Objects

All RFC objects follow the same pattern: `Get/SetParamBoolValue` with `Enable` parameter.

| Object Prefix | Init Function | DeInit Function | Source Line (Get/Set) |
|--------------|---------------|-----------------|----------------------|
| `AdvancedParentalControl_RFC` | `CosaAdvPCInit` | `CosaAdvPCDeInit` | L2272/L2324 |
| `PrivacyProtection_RFC` | `CosaAdvPPInit` | `CosaAdvPPDeInit` | L2397/L2449 |
| `DeviceFingerPrintICMPv6_RFC` | `CosaAdvDFIcmpv6Init` | `CosaAdvDFIcmpv6DeInit` | L2522/L2577 |
| `WS_Discovery_Analysis_RFC` | `CosaWSDisInit` | `CosaWSDisDeInit` | L2656/L2706 |
| `AdvancedSecurityOTM_RFC` | `CosaAdvSecOTMInit` | `CosaAdvSecOTMDeInit` | L2779/L2829 |
| `AdvSecAgentRaptr_RFC` | `CosaAdvSecAgentRaptrInit` | N/A (enable-only) | L2902/L2952 |
| `AdvanceSecurityUserSpace_RFC` | `CosaAdvSecUserSpaceInit` | N/A (DeInit commented out) | L3030/L3080 |
| `Levl_RFC` | `CosaLevlInit` | `CosaLevlDeInit` | L3163/L3215 |
| `WifiDataCollection_RFC` | `CosaAdvWifiDataCollectionInit` | `CosaAdvWifiDataCollectionDeInit` | L3290/L3338 |
| `AdvSecAgent_RFC` | `CosaAdvSecAgentInit` | `CosaAdvSecAgentDeInit` | L3409/L3457 |
| `AdvSecSafeBrowsing_RFC` | `CosaAdvSecSafeBrowsingInit` | `CosaAdvSecSafeBrowsingDeInit` | L3535/L3583 |
| `AdvSecCujoTelemetryWiFiFP_RFC` | `CosaAdvSecCujoTelemetryWiFiFPInit` | `CosaAdvSecCujoTelemetryWiFiFPDeInit` | L3661/L3711 |
| `AdvanceSecurityCujoTracer_RFC` | `CosaAdvSecCujoTracerInit` | `CosaAdvSecCujoTracerDeInit` | L3784/L3834 |
| `AdvanceSecurityCujoTelemetry_RFC` | `CosaAdvSecCujoTelemetryInit` | `CosaAdvSecCujoTelemetryDeInit` | L3908/- |
| `AdvSecSentryAtTheEdge_RFC` | `CosaAdvSecSATEInit` | `CosaAdvSecSATEDeInit` | -/- |
| `AdvSecTCPTrackerFilterDevices_RFC` | `CosaAdvSecTCPTrackerFilterDevicesInit` | `CosaAdvSecTCPTrackerFilterDevicesDeInit` | -/- |

---

## 2. Core Internal API (`cosa_adv_security_internal.c`)

### 2.1 Lifecycle Management

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaAdvSecInit()` | None | `ANSC_STATUS` | Master enable — loads modules, creates ipsets, starts agent and features |
| `CosaAdvSecDeInit()` | None | `ANSC_STATUS` | Master disable — stops features, stops agent, flushes ipsets, unloads modules |
| `CosaAdvSecStartFeatures(advsec_feature_type type)` | `ADVSEC_SAFEBROWSING`, `ADVSEC_SOFTFLOWD`, or `ADVSEC_ALL` | `ANSC_STATUS` | Start specific features via `v_secure_system` → scripts |
| `CosaAdvSecStopFeatures(advsec_feature_type type)` | Same as above | `ANSC_STATUS` | Stop specific features |

### 2.2 Feature Init/DeInit Pairs

Each RFC feature has a paired Init/DeInit that persists state to syscfg and calls `advsec_restart_agent()`:

| Init | DeInit | syscfg Key |
|------|--------|------------|
| `CosaAdvPCInit` | `CosaAdvPCDeInit` | `Adv_PCRFCEnable` |
| `CosaAdvPPInit` | `CosaAdvPPDeInit` | `Adv_PPRFCEnable` |
| `CosaAdvDFIcmpv6Init` | `CosaAdvDFIcmpv6DeInit` | `Adv_DFICMPv6RFCEnable` |
| `CosaWSDisInit` | `CosaWSDisDeInit` | `Adv_WSDisAnaRFCEnable` |
| `CosaAdvSecOTMInit` | `CosaAdvSecOTMDeInit` | `Adv_OTMRFCEnable` |
| `CosaAdvSecUserSpaceInit` | `CosaAdvSecUserSpaceDeInit` | `Adv_AdvSecUserSpaceRFCEnable` |
| `CosaLevlInit` | `CosaLevlDeInit` | `Adv_LevlRFCEnable` |
| `CosaAdvWifiDataCollectionInit` | `CosaAdvWifiDataCollectionDeInit` | `Adv_WifiDataCollectionRFCEnable` |
| `CosaAdvSecAgentInit` | `CosaAdvSecAgentDeInit` | `Adv_AdvSecAgentRFCEnable` |
| `CosaAdvSecSafeBrowsingInit` | `CosaAdvSecSafeBrowsingDeInit` | `Adv_AdvSecSafeBrowsingRFCEnable` |
| `CosaAdvSecCujoTelemetryWiFiFPInit` | `CosaAdvSecCujoTelemetryWiFiFPDeInit` | `Adv_AdvSecCujoTelemetryWiFiFPRFCEnable` |
| `CosaAdvSecCujoTracerInit` | `CosaAdvSecCujoTracerDeInit` | `Adv_AdvSecCujoTracerRFCEnable` |
| `CosaAdvSecCujoTelemetryInit` | `CosaAdvSecCujoTelemetryDeInit` | `Adv_AdvSecCujoTelemetryRFCEnable` |
| `CosaAdvSecSATEInit` | `CosaAdvSecSATEDeInit` | `Adv_SATERFCEnable` |
| `CosaAdvSecTCPTrackerFilterDevicesInit` | `CosaAdvSecTCPTrackerFilterDevicesDeInit` | `Adv_TCPTrackerFilterDevicesEnable` |
| `CosaAdvSecAgentRaptrInit` | `CosaAdvSecAgentRaptrDeInit` | N/A (enable-only) |

### 2.3 Parental Control / Privacy Protection

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaStartAdvParentalControl(BOOL update_status)` | Whether to update status | `ANSC_STATUS` | Start parental control via script `-startAdvPC` |
| `CosaStopAdvParentalControl(BOOL update_status)` | Whether to update status | `ANSC_STATUS` | Stop parental control via script `-stopAdvPC` |
| `CosaStartPrivacyProtection(BOOL update_status)` | Whether to update status | `ANSC_STATUS` | Start privacy protection via script `-startPrivProt` |
| `CosaStopPrivacyProtection(BOOL update_status)` | Whether to update status | `ANSC_STATUS` | Stop privacy protection via script `-stopPrivProt` |

### 2.4 Rabid Framework Controls

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaRabidSetMemoryLimit(hThisObject, uValue)` | Object handle, value in MB | `ANSC_STATUS` | Set agent memory hard limit (min: 45 MB) |
| `CosaRabidSetMacCacheSize(hThisObject, uValue)` | Object handle, value | `ANSC_STATUS` | Set MAC cache size (max: 32768) |
| `CosaRabidSetDNSCacheSize(hThisObject, uValue)` | Object handle, value | `ANSC_STATUS` | Set DNS cache size (max: 32768) |

### 2.5 Configuration Persistence

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaGetSysCfgString(setting, pValue, pulSize)` | Key name, buffer, buffer size | `ANSC_STATUS` | Read string from syscfg |
| `CosaSetSysCfgString(setting, pValue)` | Key name, value string | `ANSC_STATUS` | Write string to syscfg |
| `CosaGetSysCfgUlong(setting, value)` | Key name, value pointer | `ANSC_STATUS` | Read ULONG from syscfg |
| `CosaSetSysCfgUlong(setting, value)` | Key name, ULONG value | `ANSC_STATUS` | Write ULONG to syscfg |

### 2.6 Logging Controls

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaAdvSecGetLoggingPeriod()` | None | `ANSC_STATUS` | Read logging period from `g_pAdvSecAgent` |
| `CosaAdvSecSetLoggingPeriod(ULONG value)` | Period in minutes | `ANSC_STATUS` | Set logging period, signal `logCond` to wake logger thread |
| `CosaAdvSecSetLookupTimeout(ULONG value)` | Timeout value | `ANSC_STATUS` | Set DNS lookup timeout (max: 6000) |
| `advsec_start_logger_thread()` | None | `void` | Spawn `advsec_logger_th` if fingerprinting enabled |
| `advsec_logger_th(void *arg)` | Thread arg (unused) | `void*` | Periodic logger: runs `advsec_log_fp_status.sh` and `advsec_cpu_mem_recovery.sh` |

### 2.7 Sysevent Handling

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `advsec_sysevent_init()` | None | `int` | Initialize sysevent connection |
| `advsec_handle_sysevent_async()` | None | `void` | Spawn sysevent handler thread |
| `advsec_sysevent_handler_th(void *arg)` | Thread arg | `void*` | Main sysevent listener loop |
| `advsec_sysvent_listener()` | None | `int` | Block-wait for next sysevent |
| `advsec_handle_sysevent_notification(event, val)` | Event name, value | `void` | Dispatch event to handler |
| `advsec_check_sysevent_status(fd, token)` | File descriptor, token | `int` | Check current event states on startup |
| `advsec_sysvent_close()` | None | `int` | Close sysevent connection |

### 2.8 RBUS Event Consumers

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `eventReceiveHandler(handle, event, subscription)` | RBUS handle, event, subscription | `void` | WAN failover handler (`WAN_FAILOVER_SUPPORTED`) |
| `wifiEventReceiveHandler(handle, event, subscription)` | RBUS handle, event, subscription | `void` | WiFi LEVL change handler (`WIFI_DATA_COLLECTION`) |

### 2.9 WiFi / RBUS Parameter Access

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `Wifi_Get_Status(pParamName)` | TR-181 param name | `BOOL` | Get boolean status via RBUS |
| `Wifi_GetParameterValue(pParamName, pReturnVal)` | Param name, buffer | `ANSC_STATUS` | Get string value via RBUS |
| `Wifi_SetParameterValue(paramName, bValue)` | Param name, bool value | `ANSC_STATUS` | Set boolean value via RBUS |

### 2.10 Utility Functions

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `Is_Device_Finger_Print_Enabled()` | None | `BOOL` | Check if fingerprinting is enabled |
| `Is_Device_Finger_Print_Enabled_Completed()` | None | `BOOL` | Check if fingerprinting init completed |
| `Is_Agent_Initialization_Completed()` | None | `BOOL` | Check if agent is fully initialized |
| `Advsec_getPartnerBasedURL(char *url)` | Buffer for URL | `BOOL` | Fetch redirector URL from PAM via CCSP base |
| `Advsec_SetDefaultsUrl()` | None | `void` | Set default endpoint URL from partner config |
| `advsec_create_dir(char *path)` | Directory path | `void` | Create directory with `mkdir` |
| `advsec_write_to_file(fpath, str)` | File path, string | `BOOL` | Write string to file |
| `advsec_read_from_file(fpath, str, size)` | File path, buffer, size | `BOOL` | Read string from file |
| `advsec_update_feature_status(syscfg, new_val, curr_val)` | Key, new bool, current bool ptr | `ANSC_STATUS` | Update syscfg and in-memory state |
| `get_advSysEvent_type_from_name(name, type_ptr)` | Event name, type pointer | `int` (1=found) | Map event name string to enum |
| `CosaAdvSecFetchSbConfig(paramName, pValue, pUlSize, puLong)` | Param, buffers | `ANSC_STATUS` | Fetch SafeBrowsing config from agent |
| `WaitForLoggerTimeout(ULONG period)` | Period in seconds | `BOOL` | Wait on `logCond` with timeout |

### 2.11 WiFi Data Collection

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `CosaAdvWifiDataConsumerInit()` | None | `ANSC_STATUS` | Initialize WiFi data consumer socket |
| `CosaAdvWifiDataConsumerDeInit()` | None | `ANSC_STATUS` | Deinitialize WiFi data consumer |
| `CosaAdvWifiDataCollectionInit(hThisObject)` | Object handle | `ANSC_STATUS` | Enable WiFi data collection RFC |
| `CosaAdvWifiDataCollectionDeInit(hThisObject)` | Object handle | `ANSC_STATUS` | Disable WiFi data collection RFC |
| `wifidcl_init_precheck()` | None | `int` | Verify WiFi subsystem readiness via RBUS |

---

## 3. WebConfig API (`cosa_adv_security_webconfig.c`)

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `advsec_webconfig_init()` | None | `void` | Register WebConfig subdoc with framework |
| `advsec_webconfig_get_blobversion(subdoc)` | Subdoc name | `uint32_t` | Get stored blob version |
| `advsec_webconfig_set_blobversion(subdoc, version)` | Subdoc name, version | `int` | Set blob version |
| `advsec_webconfig_process_request(Data)` | `advsecuritydoc_t*` cast as `void*` | `pErr` | Process incoming webconfig blob |
| `advsec_webconfig_rollback()` | None | `int` | Rollback on blob processing failure |
| `advsec_webconfig_free_resources(arg)` | `advsecuritydoc_t*` cast as `void*` | `void` | Free allocated blob resources |
| `advsec_webconfig_handle_blob(feature)` | `advsecurityparam_t*` | `int` | Apply feature states from blob |

---

## 4. Msgpack Serialization (`advsecurity_param.c` / `advsecurity_param.h`)

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `advsecuritydoc_convert(buf, len)` | Binary buffer, length | `advsecuritydoc_t*` (NULL on error) | Deserialize msgpack → struct |
| `advsecuritydoc_destroy(d)` | Document pointer | `void` | Free deserialized document |
| `advsecuritydoc_strerror(errnum)` | errno value | `const char*` | Get error description string |
| `process_advsecurityparams(e, map)` | Param struct, msgpack map | `int` | Parse parameters from msgpack map |
| `process_advsecuritydoc(ad, num, ...)` | Document, count, varargs | `int` | Parse full document with sub-documents |

**Data Structures**:

```c
typedef struct {
    bool  fingerprint_enable;
    bool  softflowd_enable;
    bool  safebrowsing_enable;
    bool  parental_control_activate;
    bool  privacy_protection_activate;
} advsecurityparam_t;

typedef struct {
    advsecurityparam_t  *param;
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
} advsecuritydoc_t;
```

---

## 5. SSP (Service Support Process) (`source/AdvSecuritySsp/`)

### 5.1 Main Entry (`ssp_main.c`)

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `main(argc, argv)` | Command line args | `int` | Process entry point — daemonize, init CCSP, call `drop_root()` |
| `drop_root()` | None | `void` | Drop root privileges for cujo-agent (checks blocklist) |
| `isCujoBlocklisted()` | None | `BOOL` | Check if non-root mode is blocklisted for this device |
| `cmd_dispatch(command)` | Command enum | `int` | Dispatch SSP lifecycle commands |
| `sig_handler(sig)` | Signal number | `void` | Handle SIGTERM/SIGINT for graceful shutdown |
| `daemonize()` | None | `void` | Fork into background daemon |
| `_print_stack_backtrace()` | None | `void` | Print stack trace on crash (debug) |
| `get_gSubsystem_type_from_name(name, type_ptr)` | Arg name, type pointer | `int` | Parse subsystem type from CLI arguments |

### 5.2 Actions (`ssp_action.c`)

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `ssp_create_advsec()` | None | `ANSC_STATUS` | Create CCSP component (register with CR) |
| `ssp_engage_advsec()` | None | `ANSC_STATUS` | Engage component (start serving TR-181) |
| `ssp_cancel_advsec()` | None | `ANSC_STATUS` | Cancel/shutdown component |
| `ssp_AdvSecCCDmGetLoggingEnabled()` | None | `BOOL` | Get CCSP diagnostic logging state |
| `ssp_AdvSecCCDmSetLoggingEnabled(bEnabled)` | Boolean | `ANSC_STATUS` | Set CCSP diagnostic logging state |
| `ssp_AdvSecCCDmSetLoggingLevel(LogLevel)` | Level enum | `ANSC_STATUS` | Set CCSP trace log level |
| `ssp_AdvSecCCDmApplyChanges()` | None | `ANSC_STATUS` | Apply diagnostic config changes |

---

## 6. Plugin Registration (`plugin_main.c`)

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `COSA_Init(uMaxVersionSupported, hCosaPlugInfo, phContext)` | Version, plugin info, context out | `int` | Register all 40+ DML handler functions with CCSP framework |

Registers: `CosaSecurityCreate()` → `CosaSecurityInitialize()` → all Get/Set/Validate/Commit/Rollback handlers for every TR-181 object.

**Globals set**: `g_pAdvSecAgent` (singleton), `g_cujoagent_dcl` (WiFi data collection, conditional on `WIFI_DATA_COLLECTION`)

---

## 7. WiFi Data Collection API (`cujoagent_dcl_api.c`)

Low-level API for cujo-agent WiFi fingerprint data collection via Unix domain socket.

### 7.1 Consumer Lifecycle

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `cujoagent_socket_init(consumer)` | Consumer struct | `int` | Initialize Unix domain socket |
| `cujoagent_notify_events_init(consumer)` | Consumer struct | `int` | Initialize eventfd-based notification |
| `cujoagent_consumer_init(consumer)` | Consumer struct | `int` | Full consumer initialization |
| `cujoagent_consumer_deinit(consumer)` | Consumer struct | `void` | Teardown consumer, close all FDs |

### 7.2 Communication

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `cujoagent_send_version_tlv(sock_fd, paddr, ...)` | Socket, address | `int` | Send version TLV handshake to agent |
| `cujoagent_tlv_handshake(sock_fd, paddr, ...)` | Socket, address | `int` | Perform TLV handshake with cujo-agent |
| `cujoagent_emit_event_tlv(tag, data, ...)` | TLV tag, data | `int` | Send event TLV to agent |
| `cujoagent_write_event(eventfd, notify)` | Event FD, notification type | `int` | Write notification to eventfd |
| `cujoagent_wait_for_event(epoll_fd, notify, ...)` | Epoll FD, notification | `int` | Block-wait for specific event |

### 7.3 Data Collection Threads

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `cujoagent_socket_loop(void *arg)` | Consumer struct | `void*` | Main socket communication loop thread |
| `cujoagent_fifo_loop(void *arg)` | Consumer struct | `void*` | FIFO reader loop thread |
| `cujoagent_l1_collector(void *arg)` | Collector context | `void*` | L1 (Layer 1) data collection thread per MAC |
| `cujoagent_spawn_loop(start_routine, ...)` | Thread function, args | `int` | Spawn a loop thread with error handling |

### 7.4 Utility

| Function | Inputs | Output | Description |
|----------|--------|--------|-------------|
| `cujoagent_bytes_to_mac_str(mac, key)` | MAC bytes, string buffer | `char*` | Convert MAC bytes to colon-separated string |
| `cujoagent_timestamp()` | None | `uint64_t` | Get monotonic timestamp in milliseconds |
| `cujoagent_copy_to(dst, dst_len, src)` | Dest buffer, length, source | `size_t` | Safe string copy with bounds |
| `cujoagent_event_type(client_state)` | Client state enum | `int` | Map client state to event type |
| `cujoagent_new_station_event(...)` | Station info | `void` | Handle new WiFi station association event |
| `cujoagent_update_consumer_wifi_structs(...)` | Consumer, WiFi data | `void` | Update consumer internal WiFi state |
| `cujoagent_update_decoded_wifi_structs(...)` | Consumer, decoded data | `void` | Update decoded WiFi structures |
| `cujoagent_close_if_valid(fd)` | File descriptor pointer | `void` | Close FD if valid (≥ 0), set to -1 |
| `cujoagent_close_event_fds(consumer)` | Consumer struct | `void` | Close all event FDs in consumer |

---

## 8. Shell Scripts (`scripts/`)

### 8.1 `start_adv_security.sh` — Main Entry Point

**Usage**: `start_adv_security.sh <flag> [args...]`

| Flag | Function Called | Description |
|------|----------------|-------------|
| `-enable` | `start_advanced_security` | Full agent enable (modules + ipsets + agent + features) |
| `-disable` | `stop_agent_services` | Full agent disable |
| `-start sb sf` | `start_agent_services` | Start specific features (sb=SafeBrowsing, sf=Softflowd) |
| `-stop sb sf` | `stop_agent_services` | Stop specific features |
| `-startAdvPC` | `advanced_parental_control_setup` | Start advanced parental control |
| `-stopAdvPC` | `advanced_parental_control_setup` | Stop advanced parental control |
| `-startPrivProt` | `privacy_protection_setup` | Start privacy protection |
| `-stopPrivProt` | `privacy_protection_setup` | Stop privacy protection |
| `-getSafebroConfig` | `advsec_agent_get_safebro_config` | Fetch SafeBrowsing config from agent |
| `-enableWifiDCL` | `enable_wifidatacollection` | Enable WiFi data collection |
| `-disableWifiDCL` | `disable_wifidatacollection` | Disable WiFi data collection |
| `-enableLevl` | `enable_levl` | Enable LEVL |
| `-disableLevl` | `disable_levl` | Disable LEVL |
| `-enableRaptr` | `enable_raptr` | Enable Raptr framework |
| `-disableRaptr` | `disable_raptr` | Disable Raptr framework |

**RFC Toggle Flags** (all call `advsec_restart_agent`):

| Flag | Description |
|------|-------------|
| `-enableOTM` / `-disableOTM` | OTM RFC |
| `-enableUserSpace` / `-disableUserSpace` | UserSpace RFC |
| `-enableAgent` / `-disableAgent` | Agent RFC |
| `-enableSafeBrowsingRFC` / `-disableSafeBrowsingRFC` | SafeBrowsing RFC |
| `-enableWSDiscovery` / `-disableWSDiscovery` | WS-Discovery RFC |
| `-enableCujoTelemetryWiFiFP` / `-disableCujoTelemetryWiFiFP` | CujoTelemetry WiFi FP RFC |
| `-enableCujoTracer` / `-disableCujoTracer` | CujoTracer RFC |
| `-enableCujoTelemetry` / `-disableCujoTelemetry` | CujoTelemetry RFC |
| `-enableSATE` / `-disableSATE` | SATE RFC |
| `-enableTCPTrackerFilterDevices` / `-disableTCPTrackerFilterDevices` | TCPTracker Filter Devices RFC |

**Internal Functions**:

| Function | Description |
|----------|-------------|
| `start_device_services()` | Pre-start: bridge mode check, iptables rule verification, Raptr rule setup |
| `start_agent_services()` | Start agent + enable selected features |
| `stop_agent_services()` | Stop features + stop agent + flush ipsets |
| `start_advanced_security()` | Full lifecycle: module load → ipset create → agent start → features |
| `enable_safebro_iprules()` | Add SafeBrowsing iptables rules |
| `disable_safebro_iprules()` | Remove SafeBrowsing iptables rules |
| `do_firewall_restart(mode)` | Trigger firewall restart (optional "wait" for synchronous) |

### 8.2 `advsec.sh` — Environment & Agent Control

Sources: environment variables, paths, telemetry markers. Provides utility functions:

| Function | Description |
|----------|-------------|
| `advsec_is_agent_installed()` | Check if cujo-agent binary exists |
| `advsec_start_agent()` | Start cujo-agent daemon process |
| `advsec_stop_agent()` | Stop cujo-agent daemon process |
| `advsec_wait_for_agent()` | Block until agent is responsive |
| `advsec_is_alive()` | Check if agent process is running |
| `advsec_stop_process()` | SIGTERM + wait for process exit |
| `advsec_restart_agent(reason)` | Full restart cycle: stop → cleanup → reload modules → recreate ipsets → start |
| `advsec_agent_start_fp()` | `cujo-agent-feature on "fingerprint"` |
| `advsec_agent_start_sb()` | `cujo-agent-feature on "safebro.reputation"` |
| `advsec_agent_start_sf()` | `cujo-agent-feature on "tcptracker"` |
| `advsec_agent_stop_fp()` | `cujo-agent-feature off "fingerprint"` |
| `advsec_agent_stop_sb()` | `cujo-agent-feature off "safebro.reputation"` |
| `advsec_agent_stop_sf()` | `cujo-agent-feature off "tcptracker"` |
| `start_adv_parental_control()` | `cujo-agent-feature on "appblocker"` + `on "iotblocker"` |
| `stop_adv_parental_control()` | `cujo-agent-feature off "appblocker"` + `off "iotblocker"` |
| `start_privacy_protection()` | `cujo-agent-feature on "safebro.trackerblock"` |
| `stop_privacy_protection()` | `cujo-agent-feature off "safebro.trackerblock"` |
| `start_app_blocker()` | `cujo-agent-feature on "appblocker"` |
| `stop_app_blocker()` | `cujo-agent-feature off "appblocker"` |
| `start_iot_blocker()` | `cujo-agent-feature on "iotblocker"` |
| `stop_iot_blocker()` | `cujo-agent-feature off "iotblocker"` |
| `advsec_module_load()` | Load nflua kernel modules (nflua, luaconntrack, luadata, lunatik) |
| `advsec_module_unload()` | Unload nflua kernel modules |
| `advsec_kernel_module_load()` | Load individual kernel module with `insmod` |
| `advsec_kernel_module_unload()` | Unload individual kernel module with `rmmod` |
| `advsec_initialize_nfq_ct()` | Initialize nfnetlink_queue and conntrack accounting |
| `advsec_agent_create_ipsets()` | Create ipsets: `cujo_fingerprint`, `cujo_iotblock_mac/ip4/ip6` |
| `advsec_agent_flush_ipsets()` | Flush and destroy all ipsets |
| `advsec_agent_restart_needed()` | Check if restart is required based on sentinel files |
| `advsec_cleanup_config()` | Clean up all configuration files |
| `advsec_cleanup_config_agent()` | Clean up agent-specific config |
| `advsec_get_agent_group_name()` | Get the user/group name for agent process |
| `advsec_agent_loglevel()` | Set agent log level |
| `advsec_agent_get_safebro_config()` | Fetch SafeBrowsing config via `cujo-agent-status safebro-config` |
| `wait_for_lanip()` | Block until LAN IP is available |

### 8.3 `advsec_log_fp_status.sh` — Telemetry Status

| Function | Description |
|----------|-------------|
| `check_status()` | Emit all telemetry markers based on sentinel file and syscfg state |

### 8.4 `advsec_cpu_mem_recovery.sh` — Health Monitor

| Function | Description |
|----------|-------------|
| `get_agent_pid_list()` | Collect PIDs of all cujo-agent processes |
| `get_agent_cpu_time_spent()` | Sample CPU time from `/proc/<pid>/stat` |
| Main script body | Compare CPU/memory against thresholds, trigger restart if exceeded |

---

## 9. Build System Tools

### 9.1 `configure.ac`

Autoconf configuration defining:
- Package: `CcspAdvSecurity`
- Conditional features via `AM_CONDITIONAL`: `WIFI_DATA_COLLECTION`, `WAN_FAILOVER_SUPPORTED`, `DOWNLOADMODULE_ENABLE`, etc.
- Header/library checks for dependencies

### 9.2 `Makefile.am` (source/)

- Builds `libcosa_adv_security.la` (shared library — DML plugin)
- Builds `CcspAdvSecuritySsp` (executable — SSP daemon)
- Conditional compilation based on `configure.ac` flags

---

## 10. Cross-Reference: Function → Script → Agent Feature

End-to-end mapping from C function to cujo-agent feature:

| C API Call | Shell Script Flag | Script Function | Agent Command |
|------------|-------------------|-----------------|---------------|
| `CosaAdvSecInit()` | `-enable` | `start_advanced_security()` | `cujo-agent-feature on "fingerprint"` |
| `CosaAdvSecDeInit()` | `-disable` | `stop_agent_services()` | `cujo-agent-feature off "fingerprint"` |
| `CosaAdvSecStartFeatures(SB)` | `-start sb null` | `start_advsec_safe_browsing()` | `cujo-agent-feature on "safebro.reputation"` |
| `CosaAdvSecStartFeatures(SF)` | `-start null sf` | `start_advsec_softflowd()` | `cujo-agent-feature on "tcptracker"` |
| `CosaAdvSecStartFeatures(ALL)` | `-start sb sf` | Both | Both |
| `CosaStartAdvParentalControl()` | `-startAdvPC` | `start_adv_parental_control()` | `on "appblocker"` + `on "iotblocker"` |
| `CosaStopAdvParentalControl()` | `-stopAdvPC` | `stop_adv_parental_control()` | `off "appblocker"` + `off "iotblocker"` |
| `CosaStartPrivacyProtection()` | `-startPrivProt` | `start_privacy_protection()` | `on "safebro.trackerblock"` |
| `CosaStopPrivacyProtection()` | `-stopPrivProt` | `stop_privacy_protection()` | `off "safebro.trackerblock"` |
