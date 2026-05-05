# CcspAdvSecurity — Data Flow

This document explains how data moves through the CcspAdvSecurity component: input sources, processing pipelines, output destinations, log generation, and alert lifecycle.

---

## 1. Input → Processing → Output

### 1.1 TR-181 Data Model Path (CCSP Message Bus)

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐     ┌──────────────────────┐
│ dmcli / WebPA │────▶│ DML SetParam*   │────▶│ CosaAdvSec*Init()    │────▶│ syscfg set       │────▶│ v_secure_system()    │
│ (external)    │     │ (dml.c)         │     │ (internal.c)         │     │ (persistence)    │     │ → shell scripts      │
└──────────────┘     └─────────────────┘     └──────────────────────┘     └─────────────────┘     └──────────────────────┘
                                                                                                          │
                                                                                                          ▼
                                                                                              ┌──────────────────────┐
                                                                                              │ cujo-agent -feature  │
                                                                                              │ on/off <feature>     │
                                                                                              └──────────────────────┘
```

**Example — Enable Device Fingerprinting:**

1. **Input**: `dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable bool true`
2. **DML handler**: `DeviceFingerPrint_SetParamBoolValue()` validates and calls `CosaAdvSecInit()`
3. **Persistence**: `CosaSetSysCfgUlong("X_RDKCENTRAL-COM_DeviceFingerPrint.Enable", 1)`
4. **Shell exec**: `v_secure_system("start_adv_security.sh -enable &")`
5. **Agent control**: Script calls `cujo-agent-feature on "fingerprint"`
6. **Kernel enforcement**: nflua modules + ipsets loaded, iptables CUJO chains created

**Example — Enable SafeBrowsing + Softflowd together:**

1. `CosaAdvSecStartFeatures(ADVSEC_ALL)` called
2. Script receives `-start sb sf` or `-enable sb sf` flags
3. Both features toggled in a single agent invocation

### 1.2 WebConfig (Cloud-Driven) Path

```
┌────────────┐     ┌──────────────────────┐     ┌──────────────────────────────┐     ┌───────────────────────┐
│ Cloud       │────▶│ msgpack blob          │────▶│ advsecuritydoc_convert()     │────▶│ advsec_webconfig_     │
│ WebConfig   │     │ (binary)              │     │ → advsecuritydoc_t struct    │     │ process_request()    │
└────────────┘     └──────────────────────┘     └──────────────────────────────┘     └───────────────────────┘
                                                                                             │
                                                                                             ▼
                                                                                  ┌───────────────────────┐
                                                                                  │ advsec_webconfig_     │
                                                                                  │ handle_blob()         │
                                                                                  └───────────────────────┘
```

**WebConfig data structure** (`advsecurity_param.h`):

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
    char *       subdoc_name;       // must match "advsecurity"
    uint32_t     version;
    uint16_t     transaction_id;
} advsecuritydoc_t;
```

- **Input**: msgpack-encoded binary blob from cloud
- **Deserialization**: `advsecuritydoc_convert(buf, len)` via `comp_helper_convert()`
- **Validation**: subdoc name checked via `strcmp_s()` against `"advsecurity"`
- **Processing**: `advsec_webconfig_handle_blob()` applies feature states
- **Rollback**: `advsec_webconfig_rollback()` on failure
- **Cleanup**: `advsec_webconfig_free_resources()` frees allocated memory
- **Versioning**: `advsec_webconfig_get_blobversion()` / `set_blobversion()` track applied config versions

### 1.3 Sysevent Bus Path

```
┌────────────────┐     ┌──────────────────────────────┐     ┌────────────────────────┐
│ System Events  │────▶│ advsec_sysevent_handler_th()  │────▶│ CosaAdvSecInit() /     │
│ (bridge_mode,  │     │ (dedicated thread)             │     │ CosaAdvSecDeInit()     │
│  cloud_host,   │     │                                │     │                        │
│  map-t,        │     │ advsec_sysvent_listener()      │     │                        │
│  wan_ifname)   │     └──────────────────────────────┘     └────────────────────────┘
└────────────────┘
```

Four registered sysevent types:

| Event | Enum | Effect |
|-------|------|--------|
| `bridge_mode` | `SYSEVENT_BRIDGE_MODE_EVENT` | Enable/disable agent based on gateway mode |
| Cloud host/IP | `SYSEVENT_CLOUD_HOST_IP` | Update cloud endpoint connection |
| MAP-T config | `SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT` | Reconfigure on MAP-T changes |
| WAN interface | `SYSEVENT_CURRENT_WAN_IFNAME_EVENT` | Adapt to WAN interface changes |

### 1.4 RBUS Event Path

```
┌──────────────────┐     ┌──────────────────────────────┐     ┌──────────────────────┐
│ RBUS Publishers  │────▶│ eventReceiveHandler()          │────▶│ Log/React             │
│                  │     │ wifiEventReceiveHandler()      │     │                       │
└──────────────────┘     └──────────────────────────────┘     └──────────────────────┘
```

- **WAN Failover** (`WAN_FAILOVER_SUPPORTED`): `eventReceiveHandler()` receives `Device.X_RDK_WanManager.CurrentActiveInterface` changes
- **WiFi Data Collection** (`WIFI_DATA_COLLECTION`): `wifiEventReceiveHandler()` receives LEVL DML changes; auto-disables WiFi data collection when LEVL goes false

### 1.5 Configuration Persistence Flow

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────────────┐
│ Feature      │────▶│ CosaSetSysCfg    │────▶│ syscfg persistent store  │
│ Init/DeInit  │     │ Ulong/String()   │     │ (survives reboot)        │
└──────────────┘     └──────────────────┘     └──────────────────────────┘
                             ▲
                             │ Restore on startup
┌──────────────┐     ┌──────────────────┐
│ CosaAdvSec   │────▶│ CosaGetSysCfg    │
│ Initialize() │     │ Ulong/String()   │
└──────────────┘     └──────────────────┘
```

18 syscfg keys restored at initialization:

| Key | Feature |
|-----|---------|
| `X_RDKCENTRAL-COM_DeviceFingerPrint.Enable` | Device Fingerprinting |
| `AdvSecuritySafeBrowsing` | SafeBrowsing |
| `AdvSecuritySoftflowd` | Softflowd |
| `Adv_PCActivate` | Advanced Parental Control |
| `Adv_PPActivate` | Privacy Protection |
| `Adv_PCRFCEnable` | Parental Control RFC |
| `Adv_PPRFCEnable` | Privacy Protection RFC |
| `Adv_DFIcmpv6RFCEnable` | ICMPv6 Fingerprinting RFC |
| `Adv_WSDisAnaRFCEnable` | WS-Discovery Analysis RFC |
| `Adv_OTMRFCEnable` | OTM RFC |
| `Adv_AdvSecUserSpaceRFCEnable` | UserSpace RFC |
| `Adv_WifiDataCollectionRFCEnable` | WiFi Data Collection RFC |
| `Adv_LevlRFCEnable` | LEVL RFC |
| `Adv_AdvSecAgentRFCEnable` | Agent RFC |
| `Adv_AdvSecSafeBrowsingRFCEnable` | SafeBrowsing RFC |
| `Adv_AdvSecCujoTelemetryWiFiFPRFCEnable` | CujoTelemetry WiFi FP RFC |
| `Adv_AdvSecCujoTelemetryRFCEnable` | CujoTelemetry RFC |
| `Adv_TCPTrackerFilterDevicesEnable` | TCP Tracker Filter Devices RFC |

---

## 2. Log Generation

### 2.1 Runtime Logging (CcspTrace)

The component uses the CCSP trace framework with four severity levels:

| Level | Usage | Production |
|-------|-------|------------|
| `CcspTraceError` | Fatal failures, NULL pointers, allocation failures, RBUS errors | Always visible |
| `CcspTraceWarning` | Feature state changes, RFC toggles, recovery actions | Always visible |
| `CcspTraceInfo` | Initialization steps, parameter values, RBUS invocations | Configurable |
| `CcspTraceDebug` | MAC addresses, detailed parameter values, data sizes | Suppressed in production |

Log output is written to the standard CCSP log destination (typically `/rdklogs/logs/`).

### 2.2 Agent Log (`/rdklogs/logs/agent.txt`)

The cujo-agent writes its own log to `ADVSEC_AGENT_LOG_PATH=/rdklogs/logs/agent.txt`. Shell scripts append status messages via:

```bash
echo_t "[ADVSEC] <message>" >> ${ADVSEC_AGENT_LOG_PATH}
```

### 2.3 Logger Thread

A dedicated `advsec_logger_th` thread periodically triggers log collection:

```
┌──────────────────┐     ┌──────────────────────────────────┐     ┌─────────────────────────────┐
│ advsec_logger_th │────▶│ WaitForLoggerTimeout()            │────▶│ advsec_log_fp_status.sh     │
│ (periodic timer) │     │ (60 × MIN_LOG_TIMEOUT seconds)    │     │ check_status                │
└──────────────────┘     └──────────────────────────────────┘     └─────────────────────────────┘
                                                                           │
                                                                           ▼
                                                                  ┌─────────────────────────────┐
                                                                  │ advsec_cpu_mem_recovery.sh   │
                                                                  └─────────────────────────────┘
```

- **Period**: Configurable via `ulLoggingPeriod` (default: `ADVSEC_DEFAULT_LOG_TIMEOUT` = 1440 minutes = 24h)
- **Minimum granularity**: `ADVSEC_MIN_LOG_TIMEOUT` = 60 minutes
- **Synchronization**: `logMutex` + `logCond` protect `ulLoggingPeriod`; timeout change signals `logCond` to wake the thread
- **Thread starts only** when Device Fingerprinting is enabled (`Is_Device_Finger_Print_Enabled()`)

### 2.4 Telemetry Markers

The `advsec_log_fp_status.sh` script emits telemetry markers via `print_telemetry_log`:

| Marker | Meaning |
|--------|---------|
| `Device_Finger_Printing_enabled:true` | Fingerprinting is active |
| `ADV_SECURITY_SAFE_BROWSING_ENABLE` | SafeBrowsing is active |
| `ADV_SECURITY_SOFTFLOWD_ENABLE` | Softflowd is active |
| `ADV_SECURITY_DMZ_ENABLED` | DMZ is enabled on the device |
| `ADV_SECURITY_LISTEN_ONLY_MODE` | SafeBrowsing in listen-only mode (threshold=0) |
| `ADVSEC_AGENT_HIBERNATION_STATUS:<0\|1>` | Agent hibernation state |
| `ADVANCED_PARENTAL_CONTROL_ACTIVATED` | Parental controls active |
| `ADVANCED_PARENTAL_CONTROL_DEACTIVATED` | Parental controls inactive |
| `PRIVACY_PROTECTION_ACTIVATED` | Privacy protection active |
| `PRIVACY_PROTECTION_DEACTIVATED` | Privacy protection inactive |
| `PRIVACY_PROTECTION_RFC_STATUS_ENABLED` | Privacy protection RFC enabled |
| `CUJO_AGENT_RUNNING_AS_NON_ROOT` | Agent running with dropped privileges |
| `CUJO_AGENT_RUNNING_AS_ROOT` | Agent running as root |
| `DeviceFingerPrintICMPv6.Enabled` | ICMPv6 RFC enabled |
| `ADVANCE_SECURITY_RAPTR_ENABLED` | Raptr RFC enabled |
| `ADVANCE_SECURITY_USERSPACE_ENABLED` | UserSpace RFC enabled |
| `ADVANCE_SECURITY_SAFEBROWSING_IPTABLE_RULES_ENABLED` | SafeBrowsing iptables rules active |
| `ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS:<count>` | Number of MAC addresses under parental control |

---

## 3. Alert Lifecycle

### 3.1 CPU/Memory Recovery Alert

The `advsec_cpu_mem_recovery.sh` script runs periodically (triggered by the logger thread) and implements a multi-threshold alert and recovery system:

```
┌──────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────────┐
│ Logger Thread│────▶│ advsec_cpu_mem_  │────▶│ Sample agent PID  │────▶│ Compare against      │
│ (periodic)   │     │ recovery.sh      │     │ CPU time + RSS    │     │ thresholds           │
└──────────────┘     └──────────────────┘     └───────────────────┘     └──────────────────────┘
                                                                                │
                                              ┌─────────────────────────────────┤
                                              ▼                                 ▼
                                    ┌──────────────────┐              ┌──────────────────┐
                                    │ Soft limit hit:  │              │ Hard limit hit:  │
                                    │ Log telemetry    │              │ Restart agent    │
                                    │ marker           │              │ (advsec_restart  │
                                    └──────────────────┘              │  _agent)         │
                                                                      └──────────────────┘
```

**Thresholds** (configured in `advsec_cpu_mem_recovery.sh`):

| Threshold | Default | Action |
|-----------|---------|--------|
| CPU | 45% (`MAX_CPU_THRESHOLD`) | Log + potential restart |
| Memory 1st soft limit | 40 MB (`MAX_MEM_FIRST_SOFT_LIMIT`) | Log warning telemetry |
| Memory 2nd soft limit | 45 MB (`MAX_MEM_SECOND_SOFT_LIMIT`) | Log elevated warning |
| Memory hard limit | 50 MB (`MAX_MEM_HARD_LIMIT`) | Restart agent |
| Low free memory | 10 MB (`LOWFREE_MEM_THRESHOLD`) | System-level alert |
| Sampling time | 10 seconds | Measurement window |
| Process count threshold | 3 (`AGENT_PS_COUNT_THRESHOLD`) | Multiple-process check |

The hard limit is overridden by the TR-181 parameter: `syscfg get Advsecurity_RabidMemoryLimit`.

### 3.2 DNS Lookup Exceed Alert

```
┌──────────────────┐     ┌──────────────────────────────────┐     ┌──────────────────────┐
│ cujo-agent       │────▶│ /tmp/advsec_lkup_exceed_cnt      │────▶│ CcspAdvSecurity      │
│ (runtime)        │     │ (count file)                      │     │ reads count via      │
└──────────────────┘     └──────────────────────────────────┘     │ fopen()              │
                                                                   └──────────────────────┘
```

- cujo-agent writes lookup exceed count to `/tmp/advsec_lkup_exceed_cnt`
- C code reads this file at `cosa_adv_security_internal.c:2269`
- File is cleared on agent stop: `rm ${ADVSEC_LOOKUP_EXCEED_COUNT_FILE}`
- Configurable threshold via `LookupTimeout` parameter (max: `ADVSEC_MAX_LOOKUP_TIMEOUT` = 6000)

### 3.3 Agent Restart Lifecycle

When a recovery or RFC change triggers a restart:

```
advsec_restart_agent(reason)
    ├── touch /tmp/advsec_initializing          ← mark initializing
    ├── echo "[ADVSEC] Restarting due to $reason..."
    ├── advsec_stop_agent                       ← graceful stop
    ├── advsec_cleanup_config_agent             ← clean config
    ├── sleep 5                                 ← cooldown
    ├── advsec_module_load                      ← reload nflua (if not loaded)
    ├── advsec_agent_create_ipsets              ← recreate ipsets (if missing)
    └── advsec_start_agent                      ← start agent + features
```

Restart reasons include:
- `OTM_RFC_Enabled` / `OTM_RFC_Disabled`
- `AgentUserSpace_RFC_Enabled` / `AgentUserSpace_RFC_Disabled`
- `AdvSecAgent_RFC_Enabled` / `AdvSecAgent_RFC_Disabled`
- `AgentSafeBrowsing_RFC_Enabled` / `AgentSafeBrowsing_RFC_Disabled`
- `Selfheal` (default when no reason given)

### 3.4 Firewall Restart Coordination

Feature state changes trigger firewall restarts to apply iptables rules:

```bash
sysevent set firewall-restart        # async firewall restart
do_firewall_restart "wait"           # synchronous firewall restart (blocks until complete)
```

Triggered by: SafeBrowsing enable/disable, Parental Control start/stop, Privacy Protection start/stop, UserSpace RFC toggle.

---

## 4. Sentinel File State Flow

Sentinel files in `/tmp/` coordinate state between the SSP process and shell scripts:

```
                      Agent Lifecycle
                      ══════════════

    ┌─ touch ─▶ /tmp/advsec_initializing
    │
    │  ┌─ load ──▶ nflua kernel modules
    │  │           touch /tmp/advsec_nflua_loaded
    │  │
    │  ├─ create ─▶ ipsets
    │  │            touch /tmp/advsec_ipsetlist_created
    │  │
    │  ├─ start ──▶ cujo-agent
    │  │            touch /tmp/advsec_initialized
    │  │            rm    /tmp/advsec_initializing
    │  │
    │  ├─ features:
    │  │    touch /tmp/advsec_df_enabled
    │  │    touch /tmp/advsec_safebro_enable
    │  │    touch /tmp/advsec_softflowd_enable
    │  │    touch /tmp/advsec_appblocker_enabled
    │  │
    │  └─ cloud:
    │       write /tmp/advsec_cloud_ipv4
    │       write /tmp/advsec_cloud_host
    │       touch /tmp/advsec_assoc_success
    │
    │  ┌─ shutdown:
    └──┤   touch /tmp/advsec_agent_shutdown
       │   rm    /tmp/advsec_initialized
       │   flush ipsets → rm /tmp/advsec_ipsetlist_created
       │   unload nflua → rm /tmp/advsec_nflua_loaded
       │   rm    /tmp/advsec_safebro_enable
       │   rm    /tmp/advsec_softflowd_enable
       │   rm    /tmp/advsec_df_enabled
       │   rm    /tmp/advsec_lkup_exceed_cnt
       │   rm    /tmp/cujo_xpki_cert.pem
       │   touch /tmp/advsec_agent_shutdown_complete
       └──────────────────────────────────────────
```

---

## 5. Summary Data Flow Diagram

```
                                    ┌────────────────────────────────────────────┐
                                    │            CcspAdvSecuritySsp              │
     ┌────────────┐                 │                                            │
     │ dmcli/WebPA│──TR-181 DML────▶│ ┌─────────────────┐  ┌──────────────────┐ │
     └────────────┘                 │ │ cosa_adv_        │  │ cosa_adv_        │ │
                                    │ │ security_dml.c   │  │ security_        │ │
     ┌────────────┐                 │ │ (validation)     │─▶│ internal.c       │ │
     │ WebConfig  │──msgpack blob──▶│ └─────────────────┘  │ (state machine)  │ │
     │ (Cloud)    │                 │                       │                  │ │
     └────────────┘                 │ ┌─────────────────┐  │  ┌────────────┐  │ │
                                    │ │ webconfig.c      │─▶│  │ syscfg     │  │ │
     ┌────────────┐                 │ │ (blob parsing)   │  │  │ (persist)  │  │ │
     │ Sysevent   │──events────────▶│ └─────────────────┘  │  └────────────┘  │ │
     │ Bus        │                 │                       │        │         │ │
     └────────────┘                 │ ┌─────────────────┐  │        ▼         │ │
                                    │ │ sysevent_handler │─▶│ v_secure_system  │ │
     ┌────────────┐                 │ │ (bridge_mode,    │  │        │         │ │
     │ RBUS Events│──subscriptions─▶│ │  WAN failover)   │  └────────┼────────┘ │
     └────────────┘                 │ └─────────────────┘           │          │
                                    │                                │          │
                                    │ ┌─────────────────┐           │          │
                                    │ │ logger_th       │           │          │
                                    │ │ (periodic)      │──────┐    │          │
                                    │ └─────────────────┘      │    │          │
                                    └──────────────────────────┼────┼──────────┘
                                                               │    │
                                    ┌──────────────────────────┼────┼──────────┐
                                    │        Shell Scripts      │    │          │
                                    │                           ▼    ▼          │
                                    │  start_adv_security.sh ◀──────┘          │
                                    │  advsec.sh                               │
                                    │  advsec_log_fp_status.sh ◀───┘           │
                                    │  advsec_cpu_mem_recovery.sh              │
                                    └──────────────────────────────────────────┘
                                                               │
                                                               ▼
                                    ┌──────────────────────────────────────────┐
                                    │           cujo-agent (daemon)            │
                                    │  ┌────────────┐  ┌───────────────────┐  │
                                    │  │ fingerprint│  │ safebro.reputation│  │
                                    │  │ tcptracker │  │ safebro.tracker   │  │
                                    │  │ apptracker │  │ appblocker        │  │
                                    │  │ iotblocker │  │                   │  │
                                    │  └────────────┘  └───────────────────┘  │
                                    └──────────────────────────────────────────┘
                                                               │
                                                               ▼
                                    ┌──────────────────────────────────────────┐
                                    │          Kernel (nflua / netfilter)      │
                                    │  nflua.ko │ luaconntrack.ko │ luadata.ko│
                                    │  iptables CUJO chains + ipsets          │
                                    └──────────────────────────────────────────┘
```
