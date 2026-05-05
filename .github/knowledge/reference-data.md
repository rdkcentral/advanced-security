# CcspAdvSecurity — Reference Data

> **Scope:** AI knowledge base for debugging, triage, and code review

## 1. Feature Type Enum

```c
typedef enum {
    ADVSEC_SAFEBROWSING = 0,
    ADVSEC_SOFTFLOWD,
    ADVSEC_ALL = 255
} advsec_feature_type;
```

Used by `CosaAdvSecStartFeatures()` and `CosaAdvSecStopFeatures()` to select which feature to start/stop.

## 2. Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `ADVSEC_MIN_LOG_TIMEOUT` | 60 (1 hour) | Minimum logging period |
| `ADVSEC_MAX_LOG_TIMEOUT` | 2880 (48 hours) | Maximum logging period |
| `ADVSEC_DEFAULT_LOG_TIMEOUT` | 1440 (24 hours) | Default logging period |
| `ADVSEC_DEFAULT_LOOKUP_TIMEOUT` | 350 | Default SafeBrowsing lookup timeout |
| `ADVSEC_MAX_LOOKUP_TIMEOUT` | 6000 | Maximum SafeBrowsing lookup timeout |
| `ADVSEC_LogLevel_ERROR` | 1 | Error log level |
| `ADVSEC_LogLevel_WARN` | 2 | Warning log level |
| `ADVSEC_LogLevel_INFO` | 3 | Info log level |
| `ADVSEC_LogLevel_VERBOSE` | 4 | Verbose log level |
| `MIN_AGENT_MEMORY_HARD_LIMIT` | 45 | Minimum agent memory hard limit (MB) |
| `MAX_RABID_MACCACHE_SIZE` | 32768 | Maximum Rabid MAC cache entries |
| `MAX_RABID_DNSCACHE_SIZE` | 32768 | Maximum Rabid DNS cache entries |
| `ADVSEC_WAIT_FOR_TIMEOUT` | 3600 (1 hour) | Initialization wait timeout |

**Note:** There is no `ADVSEC_MIN_LOOKUP_TIMEOUT` constant. The lower bound for `LookupTimeout` uses `ADVSEC_DEFAULT_LOOKUP_TIMEOUT` (350).

## 3. syscfg Keys

### Feature Activation Keys

| Variable | syscfg Key | Feature |
|----------|-----------|---------|
| `g_DeviceFingerPrintEnabled` | `Advsecurity_DeviceFingerPrint` | DeviceFingerPrint enable/disable |
| `g_AdvSecuritySBEnabled` | `Advsecurity_SafeBrowsing` | SafeBrowsing enable/disable |
| `g_AdvSecuritySFEnabled` | `Advsecurity_Softflowd` | Softflowd enable/disable |

### Feature Activate Keys (Direct)

| Feature | syscfg Key |
|---------|-----------|
| AdvancedParentalControl | `Adv_PCActivate` |
| PrivacyProtection | `Adv_PPActivate` |

### RFC Toggle Keys

| Variable | syscfg Key | RFC Feature |
|----------|-----------|-------------|
| `g_AdvParentalControlEnabled` | `Adv_PCRFCEnable` | AdvancedParentalControl RFC |
| `g_PrivacyProtectionEnabled` | `Adv_PrivProtRFCEnable` | PrivacyProtection RFC |
| `g_DeviceFingerPrintICMPv6Enabled` | `Adv_DFICMPv6RFCEnable` | DeviceFingerPrint ICMPv6 RFC |
| `g_WSDiscoveryAnalysisEnabled` | `Adv_WSDisAnaRFCEnable` | WS-Discovery Analysis RFC |
| `g_AdvSecOTMEnabled` | `Adv_AdvSecOTMRFCEnable` | OTM RFC |
| `g_AdvSecUserSpaceEnabled` | `Adv_AdvSecUserSpaceRFCEnable` | UserSpace RFC |
| `g_RaptrEnabled` | `Adv_RaptrRFCEnable` | Raptr RFC |
| `g_AdvWifiDataCollection` | `Adv_WifiDataCollectionRFCEnable` | WiFi Data Collection RFC |
| `g_LevlEnabled` | `Adv_LevlRFCEnable` | Levl RFC |
| `g_AdvSecAgentEnabled` | `Adv_AdvSecAgentRFCEnable` | AdvSecAgent RFC |
| `g_AdvSecSafeBrowsingEnabled` | `Adv_AdvSecSafeBrowsingRFCEnable` | SafeBrowsing RFC |
| `g_AdvSecCujoTelemetryWiFiFPEnabled` | `Adv_AdvSecCujoTelemetryWiFiFPRFCEnable` | CujoTelemetryWiFiFP RFC |
| `g_AdvSecCujoTracerEnabled` | `Adv_AdvSecCujoTracerRFCEnable` | CujoTracer RFC |
| `g_AdvSecCujoTelemetryEnabled` | `Adv_AdvSecCujoTelemetryRFCEnable` | CujoTelemetry RFC |
| `g_AdvSecSATEEnabled` | `Adv_SATERFCEnable` | SATE RFC |
| `g_AdvSecTCPTrackerFilterDevicesEnabled` | `Adv_TCPTrackerFilterDevicesRFCEnable` | TCPTrackerFilterDevices RFC |

## 4. Init/DeInit Function Mappings

| Feature | Init Function | DeInit Function | Script Flag |
|---------|--------------|-----------------|-------------|
| DeviceFingerPrint | `CosaAdvSecInit()` | `CosaAdvSecDeInit()` | `-enable` / `-disable` |
| SafeBrowsing | `CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING)` | `CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING)` | `-start sb null` / `-stop sb null` |
| Softflowd | `CosaAdvSecStartFeatures(ADVSEC_SOFTFLOWD)` | `CosaAdvSecStopFeatures(ADVSEC_SOFTFLOWD)` | `-start null sf` / `-stop null sf` |
| AdvancedParentalControl | `CosaStartAdvParentalControl()` | `CosaStopAdvParentalControl()` | `-startAdvPC` / `-stopAdvPC` |
| PrivacyProtection | `CosaStartPrivacyProtection()` | `CosaStopPrivacyProtection()` | `-startPrivProt` / `-stopPrivProt` |
| AdvPC RFC | `CosaAdvPCInit()` | `CosaAdvPCDeInit()` | (controls PC feature availability) |
| PrivacyProtection RFC | `CosaPrivacyProtectionInit()` | `CosaPrivacyProtectionDeInit()` | (controls PP feature availability) |
| ICMPv6 RFC | `CosaAdvSecAgentDFIcmpv6Init()` | `CosaAdvSecAgentDFIcmpv6DeInit()` | (ICMPv6 fingerprinting) |
| WS-Discovery RFC | `CosaWSDisInit()` | `CosaWSDisDeInit()` | (WS-Discovery analysis) |
| OTM RFC | `CosaAdvSecOTMInit()` | `CosaAdvSecOTMDeInit()` | (OTM mode) |
| UserSpace RFC | `CosaAdvSecUserSpaceInit()` | — (DeInit commented out) | (UserSpace; cannot disable) |
| Raptr RFC | `CosaAdvSecAgentRaptrInit()` | `CosaAdvSecAgentRaptrDeInit()` | (enable-only via TR-181) |
| Levl RFC | `CosaLevlInit()` | `CosaLevlDeInit()` | (Levl feature) |

## 5. DML Handler Registrations

All handlers registered in `plugin_main.c` via `COSA_Init()`:

| TR-181 Object | Get Bool | Set Bool | Get Ulong | Set Ulong | Get String | Set String | Validate | Commit | Rollback |
|---------------|----------|----------|-----------|-----------|------------|------------|----------|--------|----------|
| DeviceFingerPrint | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | — |
| AdvancedSecurity | — | — | — | — | — | ✓ (WebConfig) | — | — | — |
| SafeBrowsing | ✓ | ✓ | ✓ | ✓ | ✓ | — | NO-OP | NO-OP | NO-OP |
| Softflowd | ✓ | ✓ | — | — | — | — | NO-OP | NO-OP | NO-OP |
| RabidFramework | — | — | ✓ | ✓ | — | — | — | — | — |

### RFC DML Handlers (Get/Set Bool only)
| RFC Feature | Get | Set |
|-------------|-----|-----|
| AdvancedParentalControl_RFC | ✓ | ✓ |
| PrivacyProtection_RFC | ✓ | ✓ |
| DeviceFingerPrintICMPv6_RFC | ✓ | ✓ |
| WS_Discovery_Analysis_RFC | ✓ | ✓ |
| AdvancedSecurityOTM_RFC | ✓ | ✓ |
| AdvSecAgentRaptr_RFC | ✓ | ✓ |
| AdvanceSecurityUserSpace_RFC | ✓ | ✓ |
| WifiDataCollection_RFC | ✓ | ✓ |
| AdvSecAgent_RFC | ✓ | ✓ |
| AdvSecSafeBrowsing_RFC | ✓ | ✓ |
| AdvSecCujoTelemetryWiFiFP_RFC | ✓ | ✓ |
| AdvanceSecurityCujoTracer_RFC | ✓ | ✓ |
| AdvanceSecurityCujoTelemetry_RFC | ✓ | ✓ |
| AdvSecSentryAtTheEdge_RFC | ✓ | ✓ |
| AdvSecTCPTrackerFilterDevices_RFC | ✓ | ✓ |

## 6. Build Flags

| Flag | Behavior Change |
|------|-----------------|
| `WIFI_DATA_COLLECTION` | Enables WiFi data collection API, cujoagent_dcl_api, extra RFC handlers |
| `DOWNLOADMODULE_ENABLE` | Uses `/tmp/cujo_dnld` for agent download location |
| `WAN_FAILOVER_SUPPORTED` | Enables WAN failover event handling in sysevent handler |
| `_COSA_BCM_MIPS_` | Broadcom MIPS: uses dpoe_hal, ARRIS vendor name, platform-specific CM MAC |
| `_COSA_INTEL_XB3_ARM_` | Intel XB3: restricts certain RFC features (SB/CujoTelemetry/CujoTracer/SATE/TCPTracker) |
| `_COSA_DRG_TPG_` | Arris DRG/TPG platform variant |
| `CONFIG_CISCO` | Cisco platform: different vendor name |
| `PON_GATEWAY` | PON gateway: different CM MAC retrieval method |
| `_XER5_PRODUCT_REQ_` | XER5: skips certain CM MAC operations, uses RaspberryPi-like paths |
| `_SCER11BEL_PRODUCT_REQ_` | SCER11BEL: similar restrictions as XER5 |
| `_PLATFORM_RASPBERRYPI_` | Raspberry Pi development platform |
| `_PLATFORM_TURRIS_` | Turris development platform |
| `_PLATFORM_BANANAPI_R4_` | BananaPi R4 development platform |
| `_XF3_PRODUCT_REQ_` | XF3: skips certain RBUS event registration |

## 7. Sysevent Definitions

| Event | Constant | Purpose |
|-------|----------|---------|
| Bridge mode change | `ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT` = `"bridge_mode"` | Triggers agent stop in bridge mode |
| Cloud host IP | `ADVSEC_SYSEVENT_CLOUD_HOST_IP` = `"advsec_host_ip"` | Cloud connectivity changes |
| MAP-T config | `ADVSEC_SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT` = `"mapt_config_flag"` | MAP-T config changes |
| WAN interface | `ADVSEC_SYSEVENT_CURRENT_WAN_IFNAME_EVENT` = `"current_wan_ifname"` | WAN interface changes |

## 8. Data Model Structures

### Core Structure Hierarchy
```
COSA_DATAMODEL_AGENT (g_pAdvSecAgent)
├── bEnable                          # DeviceFingerPrint master enable
├── ulLoggingPeriod                  # Logging period (minutes)
├── ulLogLevel                       # Log level (1-4)
├── pAdvSec → COSA_DATAMODEL_ADVSEC
│   ├── bEnable                      # AdvancedSecurity enable
│   ├── pSafeBrows → COSA_DATAMODEL_SB
│   │   ├── bEnable                  # SafeBrowsing enable
│   │   └── ulLookupTimeout          # Lookup timeout
│   └── pSoftFlowd → COSA_DATAMODEL_SOFTFLOWD
│       └── bEnable                  # Softflowd enable
├── pAdvPC → COSA_DATAMODEL_ADVPARENTALCONTROL
├── pAdvPC_RFC → COSA_DATAMODEL_ADVPC_RFC
├── pPrivProt → COSA_DATAMODEL_PRIVACYPROTECTION
├── pPrivProt_RFC → COSA_DATAMODEL_PRIVACYPROTECTION_RFC
├── pDFIcmpv6_RFC
├── pWSDiscoveryAnalysis_RFC
├── pAdvSecOTM_RFC
├── pAdvSecUserSpace_RFC
├── pAdvWifiDataCollection_RFC
├── pLevl_RFC
├── pAdvSecAgent_RFC
├── pAdvSecSafeBrowsing_RFC
├── pAdvSecCujoTelemetryWiFiFP_RFC
├── pAdvSecCujoTracer_RFC
├── pAdvSecCujoTelemetry_RFC
├── pAdvSecSATE_RFC
├── pAdvSecTCPTrackerFilterDevices_RFC
└── pRaptr_RFC
```

## 9. Threading Model

| Thread | Function | Purpose |
|--------|----------|---------|
| Main (SSP) | `ssp_main.c:main()` | Daemon lifecycle, message bus registration |
| Logger | `advsec_logger_th()` | Periodic log flush, controlled by `logMutex`/`logCond` |
| Sysevent Handler | `advsec_sysevent_handler_th()` | Bridge mode, WAN interface, MAP-T events |

### Synchronization
| Primitive | Scope | Purpose |
|-----------|-------|---------|
| `logMutex` | `cosa_adv_security_internal.c` | Protects logging state and log period changes |
| `logCond` | `cosa_adv_security_internal.c` | Signals logger thread for period changes |
| `PTHREAD_MUTEX_INITIALIZER` | Static init | Both primitives statically initialized |

## 10. Sentinel File Paths

| File | Purpose |
|------|---------|
| `/tmp/advsec_initialized` | Agent fully initialized |
| `/tmp/advsec_initializing` | Initialization in progress |
| `/tmp/advsec_daemons_hibernating` | Daemons in hibernation |
| `/tmp/advsec_softflowd_enable` | Softflowd active |
| `/tmp/advsec_safebro_enable` | SafeBrowsing active |
| `/tmp/advsec_wifidcl_init` | WiFi data collection initialized |
| `/tmp/advsec_config_params/` | Config parameter directory |
| `/tmp/advsec_config_params/MODEL` | Device model |
| `/tmp/advsec_config_params/MANUFACTURER` | Manufacturer name |
| `/tmp/advsec_config_params/FWVER` | Firmware version |
| `/tmp/advsec_config_params/HWVER` | Hardware version |
| `/tmp/advsec_config_params/CMMAC` | CM MAC address |
| `/tmp/advsec_cloud_host` | Cloud host name |
| `/tmp/advsec_cloud_ipv4` | Cloud IPv4 address |
| `/tmp/safebro.json` | SafeBrowsing configuration |
| `/tmp/advsec_lkup_exceed_cnt` | Lookup exceed count tracking |

## 11. Failure Patterns

### Feature Activation Failures

| Pattern | Symptoms | Probable Causes | Recovery |
|---------|----------|----------------|----------|
| Feature not activating | syscfg shows enabled, but no sentinel file | cujo-agent not installed, bridge mode active | Install agent, check bridge mode |
| Feature stuck initializing | `/tmp/advsec_initializing` exists indefinitely | LAN IP not ready, script hung | Remove sentinel, restart daemon |
| RFC toggle no effect | syscfg key set but feature unchanged | Dependency RFC not enabled (e.g., UserSpace for SB-RFC) | Enable dependency first |
| SafeBrowsing not working | Enable set but no DNS interception | DeviceFingerPrint not enabled, or AdvancedSecurity not enabled | Enable parent features first |

### Configuration Failures

| Pattern | Log Signature | Resolution |
|---------|--------------|------------|
| Agent not found | `"is not installed on the device"` | Verify cujo-agent package in firmware build |
| Bridge mode block | `"Device is in Bridge Mode, do not launch agent"` | Expected behavior in bridge mode |
| CM MAC fallback | Uses `ADVSEC_DEFAULT_CM_MAC` | Fix platform HAL or dpoe_hal |
| Already initializing | `"is already being initialized"` | Wait or remove `/tmp/advsec_initializing` |

### Build Flag Misconfigurations

| Pattern | Cause | Resolution |
|---------|-------|------------|
| WiFi DCL crash | `WIFI_DATA_COLLECTION` enabled but cujoagent_dcl not linked | Verify build includes cujoagent_dcl_api |
| Missing dpoe_hal | `_COSA_BCM_MIPS_` but no dpoe_hal | Install Broadcom SDK headers |
| RFC restricted | `_COSA_INTEL_XB3_ARM_` blocks certain features | Expected — platform limitation |

### Thread Safety Notes

**Mutex-protected**: Logging period (`ulLoggingPeriod`), log level (`ulLogLevel`), log condition signaling

**Unprotected (single-writer assumed)**: All feature enable/disable booleans in `g_pAdvSecAgent` tree. These are only written from DML thread (CCSP message bus callback context).

### Special Behavioral Notes

| Feature | Behavior |
|---------|----------|
| Raptr RFC | Enable-only — `SetParamBoolValue` returns `FALSE` for disable |
| UserSpace RFC | `CosaAdvSecUserSpaceDeInit()` is commented out — cannot be disabled |
| AdvSecSafeBrowsing RFC | Requires UserSpace RFC enabled first |
| AdvSecCujoTelemetryWiFiFP RFC | Requires UserSpace RFC enabled first |
| SafeBrowsing V/C/R | Validate, Commit, Rollback are all NO-OPs. Logic in SetParamBoolValue |
| Softflowd V/C/R | Validate, Commit, Rollback are all NO-OPs. Logic in SetParamBoolValue |
