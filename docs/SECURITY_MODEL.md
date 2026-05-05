# CcspAdvSecurity — Security Model

This document describes the security architecture, policies, threat detection logic, enforcement mechanisms, and trust boundaries for the CcspAdvSecurity (Advanced Security) component.

---

## 1. Trust Boundaries

External input enters the system through four distinct trust boundaries:

### 1.1 TR-181 Data Model (CCSP Message Bus)

All `SetParam*Value` DML handlers are entry points for external configuration:

| Handler | Object | Parameters |
|---------|--------|------------|
| `DeviceFingerPrint_SetParamBoolValue` | `X_RDKCENTRAL-COM_DeviceFingerPrint` | Enable, RFC flags |
| `DeviceFingerPrint_SetParamUlongValue` | `X_RDKCENTRAL-COM_DeviceFingerPrint` | LogTimeout, LookupTimeout |
| `DeviceFingerPrint_SetParamStringValue` | `X_RDKCENTRAL-COM_DeviceFingerPrint` | SBConfig URL |
| `SafeBrowsing_SetParamBoolValue` | `SafeBrowsing` | Enable |
| `Softflowd_SetParamBoolValue` | `Softflowd` | Enable |
| `AdvancedParentalControl_SetParamBoolValue` | `AdvancedParentalControl` | Activate |
| `PrivacyProtection_SetParamBoolValue` | `PrivacyProtection` | Activate |
| `RabidFramework_SetParamUlongValue` | `RabidFramework` | MemoryLimit, MacCacheSize, DnsCacheSize |
| `AdvancedParentalControl_RFC_SetParamBoolValue` | `AdvancedParentalControl_RFC` | Enable |
| `PrivacyProtection_RFC_SetParamBoolValue` | `PrivacyProtection_RFC` | Enable |

### 1.2 WebConfig (Cloud Configuration)

The WebConfig subsystem provides a second trust boundary for cloud-driven configuration blobs:

- **Entry**: `advsec_webconfig_process_request()` in `cosa_adv_security_webconfig.c`
- **Subdoc validation**: `strcmp_s()` against `ADVSEC_WEBCONFIG_SUBDOC_NAME`
- **Rollback**: `advsec_webconfig_rollback()` on blob execution failure
- **Null safety**: Explicit NULL checks on `advsec->subdoc_name` and `advsec->param`
- **Parameters controlled**: `fingerprint_enable`, `softflowd_enable`, `safebrowsing_enable`, `parental_control_activate`, `privacy_protection_activate`

### 1.3 Sysevent Bus

The `advsec_sysevent_handler_th` thread listens for system events:

- `bridge_mode` — triggers agent enable/disable based on gateway mode
- WAN status changes (under `WAN_FAILOVER_SUPPORTED` build flag)
- Event loop runs in a dedicated thread with `advsec_sysvent_listener()`

### 1.4 cujo-agent Runtime (IPC)

The cujo-agent process runs as a separate daemon. The SSP component communicates via:

- Shell script invocations (`start_adv_security.sh`, `advsec.sh`)
- `cujo-agent-feature on|off <feature>` CLI commands
- `cujo-agent-status` for runtime queries (e.g., `safebro-config`)
- Sentinel files in `/tmp/advsec_*` for state coordination

---

## 2. Policies

### 2.1 Input Validation Policy

**URL Validation** — `isValidUrl()` in `cosa_adv_security_dml.c`:

```c
ANSC_STATUS isValidUrl(char *inputparam)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    if (urlStartsWith(inputparam, "https://"))
        returnStatus = ANSC_STATUS_FAILURE;    // reject non-HTTPS
    if (strstr(inputparam, ";"))               // command injection: semicolon
        returnStatus = ANSC_STATUS_FAILURE;
    else if (strstr(inputparam, "&"))          // command injection: ampersand
        returnStatus = ANSC_STATUS_FAILURE;
    else if (strstr(inputparam, "|"))          // command injection: pipe
        returnStatus = ANSC_STATUS_FAILURE;
    else if (strstr(inputparam, "'"))          // command injection: single quote
        returnStatus = ANSC_STATUS_FAILURE;
    return returnStatus;
}
```

> **Known weakness**: The `if`/`else if` chain means the HTTPS check and the first injection check (`";"`) are independent, but subsequent injection checks are `else if` — if `";"` is present, `"&"`, `"|"`, and `"'"` are not checked. In practice this is acceptable because any single match causes rejection.

**Numeric Parameter Bounds**:
- `MemoryLimit` ≥ `MIN_AGENT_MEMORY_HARD_LIMIT` (45 MB)
- `MacCacheSize` ≤ `MAX_RABID_MACCACHE_SIZE` (32768)
- `DnsCacheSize` ≤ `MAX_RABID_DNSCACHE_SIZE` (32768)
- `LogTimeout` ∈ [60, 2880] minutes (`ADVSEC_MIN_LOG_TIMEOUT` .. `ADVSEC_MAX_LOG_TIMEOUT`)
- `LookupTimeout` ≤ `ADVSEC_MAX_LOOKUP_TIMEOUT` (6000)

### 2.2 Shell Invocation Policy

All shell commands are executed via `v_secure_system()` — never `system()`. This prevents command injection through format-string expansion. All calls use hardcoded script paths:

```
v_secure_system("/usr/ccsp/advsec/start_adv_security.sh -enable &");
v_secure_system("/usr/ccsp/advsec/start_adv_security.sh -start sb null &");
v_secure_system("/usr/ccsp/advsec/advsec_log_fp_status.sh check_status &");
v_secure_system("/usr/ccsp/advsec/advsec_cpu_mem_recovery.sh &");
```

No user-supplied strings are interpolated into shell commands.

### 2.3 Privilege Separation Policy

- **`drop_root()`** in `ssp_main.c` controls whether cujo-agent runs as root or as the `_cujo-agent` user (`_rabid` on XB3/XF3)
- A blocklist check (`isCujoBlocklisted()`) determines if non-root mode is enabled
- When non-root is disabled, `/tmp/advsec_cujo_agent_root_priv` sentinel is created

### 2.4 Feature Dependency Policy

- **SafeBrowsing RFC** (`AdvSecSafeBrowsing_RFC`) requires `UserSpace_RFC` to be enabled
- **CujoTelemetryWiFiFP RFC** (`AdvSecCujoTelemetryWiFiFP_RFC`) requires `UserSpace_RFC` to be enabled
- **UserSpace RFC** — `DeInit` is **commented out**, making it irrevocable once enabled
- **Raptr RFC** — `SetParamBoolValue` returns `FALSE` for disable attempts (enable-only)
- **Bridge mode** — agent cannot launch when `bridge_mode == 2` (checked via `syscfg get bridge_mode`)

### 2.5 Persistence Policy

All feature enable/disable states are persisted to `syscfg` via `CosaSetSysCfgUlong()`. The 18 syscfg keys:

- `X_RDKCENTRAL-COM_DeviceFingerPrint.Enable` through `Adv_TCPTrackerFilterDevicesEnable`
- Values restored on process restart via `CosaGetSysCfgUlong()` in `CosaAdvSecInit()`

---

## 3. Threat Detection Logic

### 3.1 cujo-agent Feature Set

The cujo-agent (or `rabid` on legacy platforms) provides the following detection features, toggled via the `-feature` CLI:

| Feature Name | Purpose | Toggle Script |
|-------------|---------|---------------|
| `fingerprint` | Device identification by network behavior (MAC, DHCP, mDNS) | `advsec_start_agent_features()` |
| `safebro.reputation` | URL/domain reputation-based threat blocking | `advsec_start_agent_features()` |
| `safebro.trackerblock` | Privacy tracker blocking | `advsec_start_privacy_protection()` |
| `tcptracker` | TCP flow tracking for traffic analysis | `advsec_start_agent_features()` |
| `apptracker` | Application-layer traffic classification | `advsec_start_softflowd()` |
| `appblocker` | Application-level blocking (parental controls) | `advsec_start_adv_parental_control()` |
| `iotblocker` | IoT device access control | `advsec_start_adv_parental_control()` |

### 3.2 Safe Browsing Configuration

- Configuration retrieved via `start_adv_security.sh -getSafebroConfig`
- Runtime config from `cujo-agent-status safebro-config` → stored in `${RW_DIR}/safebro.json`
- SafeBrowsing and Softflowd DML `Validate/Commit/Rollback` handlers are **no-ops** — enable/disable happens directly in `SetParamBoolValue`

### 3.3 Device Fingerprinting

- Uses `cujo_fingerprint` ipset (hash:mac) for tracking identified devices
- ICMPv6 fingerprinting controlled by separate RFC (`DeviceFingerPrintICMPv6_RFC`)
- WS-Discovery analysis controlled by `Adv_WSDisAnaRFCEnable` syscfg key

---

## 4. Enforcement Mechanisms

The agent operates in one of two enforcement modes. The mode determines how network traffic is inspected and blocked.

### 4.0 Enforcement Modes

| | Userspace Mode | Kernel (nflua) Mode |
|--|----------------|---------------------|
| **How it works** | cujo-agent process inspects traffic in userspace via packet queuing (`nfnetlink_queue`) | Lua scripts run inside kernel via nflua netfilter modules |
| **Performance** | Higher latency, more CPU usage | Lower latency, less CPU |
| **When used** | UserSpace RFC enabled (most modern devices) | UserSpace RFC disabled (legacy devices) |
| **Sentinel** | `/tmp/advsec_userspace_enabled` exists | `/tmp/advsec_nflua_loaded` exists |
| **Kernel modules** | None loaded | nflua, luaconntrack, luadata, lunatik loaded |

**How to check which mode is active:**

```bash
# Method 1: Check sentinel files
ls /tmp/advsec_userspace_enabled    # exists → userspace mode
ls /tmp/advsec_nflua_loaded         # exists → kernel (nflua) mode

# Method 2: Check syscfg
syscfg get Adv_AdvSecUserSpaceRFCEnable
# 1 → userspace mode; 0 or empty → kernel mode

# Method 3: Check dmcli
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityUserSpace.Enable
# true → userspace; false → kernel

# Method 4: Check kernel modules
lsmod | grep nflua
# Output present → kernel mode; empty → userspace mode
```

> **Note**: Once UserSpace RFC is enabled, it cannot be disabled (DeInit is commented out in source). Most current devices default to userspace mode.

### 4.1 Kernel-Space Enforcement (nflua)

Only active when UserSpace RFC is **disabled**. Network enforcement operates at the kernel level using nflua kernel modules:

| Module | Path | Purpose |
|--------|------|---------|
| `nflua.ko` | `/lib/modules/$(uname -r)/nflua.ko` | Lua-scriptable netfilter framework |
| `luaconntrack.ko` | `/lib/modules/$(uname -r)/luaconntrack.ko` | Connection tracking integration |
| `luadata.ko` | `/lib/modules/$(uname -r)/luadata.ko` | Kernel-user data exchange |
| `lunatik.ko` | `/lib/modules/$(uname -r)/lunatik.ko` | Lua kernel runtime |
| `nfnetlink_queue.ko` | `.../kernel/net/netfilter/nfnetlink_queue.ko` | Netfilter packet queuing |

The system tracks nflua module state via the `/tmp/advsec_nflua_loaded` sentinel file and can switch between nflua mode and userspace mode at runtime.

### 4.2 Userspace Enforcement

When UserSpace RFC is enabled (`/tmp/advsec_userspace_enabled` exists), the cujo-agent handles all traffic inspection in its own process space. No nflua kernel modules are loaded. The agent uses `nfnetlink_queue` for packet queuing from netfilter to userspace.

### 4.3 Packet Filtering (iptables/ipset)

Used in **both** modes:

- **iptables chains**: Rules prefixed with `CUJO` in both IPv4 and IPv6 tables
- **ipsets created on agent start**:
  - `cujo_fingerprint` — `hash:mac` for fingerprint tracking
  - `cujo_iotblock_mac` — `hash:mac` for IoT device blocking
  - `cujo_iotblock_ip4` — `hash:ip` (inet) for IPv4 IoT blocking
  - `cujo_iotblock_ip6` — `hash:ip` (inet6) for IPv6 IoT blocking
- On shutdown: `ipset flush` + `ipset destroy` for each set
- SafeBrowsing IP rules toggled via `enable_safebro_iprules()` / `disable_safebro_iprules()`

### 4.4 Sentinel File State Machine

Feature state is tracked through sentinel files in `/tmp/`:

| Sentinel | Meaning |
|----------|---------|
| `/tmp/advsec_initializing` | Agent is starting up |
| `/tmp/advsec_initialized` | Agent is fully running |
| `/tmp/advsec_agent_shutdown` | Shutdown requested |
| `/tmp/advsec_agent_shutdown_complete` | Shutdown complete |
| `/tmp/advsec_safebro_enable` | SafeBrowsing active |
| `/tmp/advsec_softflowd_enable` | Softflowd active |
| `/tmp/advsec_df_enabled` | Device Fingerprinting active |
| `/tmp/advsec_appblocker_enabled` | App blocking active |
| `/tmp/advsec_daemons_hibernating` | Daemons in hibernation |
| `/tmp/advsec_nflua_loaded` | nflua kernel modules loaded (kernel mode) |
| `/tmp/advsec_userspace_enabled` | Userspace enforcement mode active |
| `/tmp/advsec_ipsetlist_created` | ipsets are created |

### 4.5 Conntrack Accounting

- Enabled on agent start: `sysctl -w net.netfilter.nf_conntrack_acct=1`
- Disabled on agent stop: `sysctl -w net.netfilter.nf_conntrack_acct=0`

---

## 5. Cryptographic and Identity Controls

### 5.1 Device Certificate

- xPKI device certificate stored at `/tmp/cujo_xpki_cert.pem` (`ADVSEC_DEVICE_CERT`)
- Certificate cleaned up on agent shutdown (`rm ${ADVSEC_DEVICE_CERT}`)
- Used for cloud association (agent ↔ cloud mutual TLS)

### 5.2 Cloud Association

- Cloud endpoint IP cached in `/tmp/advsec_cloud_ipv4`
- Cloud hostname cached in `/tmp/advsec_cloud_host`
- Successful association tracked via `/tmp/advsec_assoc_success`

---

## 6. Memory Safety Patterns

- **`snprintf`** used in `cosa_adv_security_internal.c` (4 instances) — no `sprintf` usage
- **`strncpy`** used for bounded string copies in webconfig handlers
- **`memset_s`** (safe memset) used with `ERR_CHK()` validation
- **`strcpy_s`** (safe strcpy with bounds) used in SSP argument parsing
- **`strcmp_s`** (safe strcmp with indicator) used in webconfig subdoc validation
- **`AnscAllocateMemory`** with explicit NULL checks after allocation
- **`AnscFreeMemory`** for paired deallocation (e.g., `pAdvSecUserSpace_RFC`)
- **Coverity fixes** referenced in comments: CID 135431 (STRING_SIZE), CID 161160 (Useless call)

---

## 7. Logging and PII Handling

### 7.1 MAC Address Logging

MAC addresses appear in debug/error logs but only in failure paths or trace-level debug:

```c
CcspTraceError(("CcspAdvSecurity: Unable to get MACAdress\n"));     // error message, no actual MAC
CcspTraceDebug(("Setting mac [%s] for CSI and CFO collection\n", client_mac_str));  // Debug only
```

MAC values are logged at `CcspTraceDebug` level (suppressed in production). Error messages reference MAC retrieval failure without exposing the value.

### 7.2 Synchronization

- `logMutex` + `logCond` protect shared logging state between the logger thread and feature threads
- `advsec_logger_th` — dedicated logging thread
- Thread-safe access to `g_pAdvSecAgent` singleton

---

## 8. Build-Time Security Flags

| Flag | Effect |
|------|--------|
| `WIFI_DATA_COLLECTION` | Enables WiFi data collection feature and `cujoagent_dcl` module |
| `_COSA_BCM_MIPS_` | Platform-specific code paths for Broadcom MIPS devices |
| `WAN_FAILOVER_SUPPORTED` | Enables WAN failover event handling in sysevent listener |
| `DOWNLOADMODULE_ENABLE` | Enables runtime module download with `TEMP_DOWNLOAD_LOCATION` prefix |
| `FEATURE_SUPPORT_INTERWORKING` | Enables interworking/hotspot integration |

---

## 9. Security Invariants

These invariants must hold for the security model to remain sound:

1. **No user input reaches shell commands** — all `v_secure_system()` calls use hardcoded script paths
2. **URL parameters are validated** — `isValidUrl()` rejects command injection characters before any URL is processed
3. **Feature dependencies are enforced** — SafeBrowsing and CujoTelemetry cannot activate without UserSpace RFC
4. **Bridge mode blocks agent** — the agent must not run in bridge mode (`bridge_mode == 2`)
5. **Irrevocable features stay enabled** — UserSpace RFC cannot be disabled; Raptr RFC cannot be disabled
6. **Kernel modules track state** — nflua loaded state is always reflected in sentinel files
7. **ipsets are cleaned on shutdown** — all CUJO ipsets are flushed and destroyed to prevent stale rules
8. **Privilege drop is checked** — `drop_root()` executes before agent launch, with blocklist override
