# Advanced Security Troubleshooting

## 1. Quick Triage Checklist

1. Process running? — `ps | grep -i CcspAdvSecuritySsp | grep -v grep`
2. Component registered? — `dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable`
3. cujo-agent running? — `ps | grep cujo-agent | grep -v grep`
4. Feature states? — Check DeviceFingerPrint, SafeBrowsing, Softflowd enables (see §6)
5. Init file present? — `ls -l /tmp/advsec_initialized`
6. Config params written? — `ls -l /tmp/advsec_config_params/`
7. WebConfig registered? — Check blob version (see §6)
8. Resource usage? — `top -bn1 | grep -E 'CcspAdvSec|cujo-agent'`

## 2. Log Sources

| Source | Location | Content |
|--------|----------|---------|
| Component logs | `journalctl -u CcspAdvSecuritySsp` | Daemon lifecycle, DML operations |
| CCSP trace | `/rdklogs/logs/ADVSEClog.txt.0` | CcspTraceInfo/Error/Warning output |
| Script output | `/rdklogs/logs/advsec_start.log` | Shell script execution traces |
| Agent logs | `/tmp/advsec/log/` or `/var/log/cujo/` | cujo-agent operational logs |
| Kernel | `dmesg` | nflua, luaconntrack module events |
| Telemetry | `/rdklogs/logs/` | Periodic status from `advsec_log_fp_status.sh` |
| Crash backtrace | `/nvram/advsecssp_backtrace` | Stack trace on fatal signals |

## Quick Log Searches for Field Debugging

Copy-paste these grep commands to quickly diagnose common field issues.

### Is the component healthy?

```bash
# Startup errors — run first
grep -i "fail\|error\|unable\|EXIT Error\|NULL" /rdklogs/logs/ADVSEClog.txt.0

# Initialization success — must see this
grep "PandMDB initiated\|Module loaded" /rdklogs/logs/ADVSEClog.txt.0

# Check all RFC states at once
grep "RFCEnable" /rdklogs/logs/ADVSEClog.txt.0
```

### Is the agent running and connected?

```bash
# Agent lifecycle in script logs
grep -i "ADVSEC.*start\|ADVSEC.*stop\|ADVSEC.*Restart\|ADVSEC.*shutdown" /rdklogs/logs/agent.txt

# Cloud association status
grep "assoc\|cloud\|websocket" /rdklogs/logs/agent.txt

# Agent not running (selfheal detected)
grep "process is not running" /rdklogs/logs/agent.txt
```

### Feature not working?

```bash
# Check which features are enabled/disabled
grep "Device_Finger_Printing_enabled\|SAFE_BROWSING\|SOFTFLOWD\|PARENTAL_CONTROL\|PRIVACY_PROTECTION" /rdklogs/logs/agent.txt

# Feature activation failures
grep "enabled:false\|not enabled\|not completed" /rdklogs/logs/ADVSEClog.txt.0

# SafeBrowsing config issues
grep -i "safebro\|fetch.*config.*failed" /rdklogs/logs/ADVSEClog.txt.0
```

### Memory/CPU issues?

```bash
# Memory and CPU stats
grep "TOTAL_RSS_MEM\|total_CPU_usage" /rdklogs/logs/agent.txt

# Memory threshold breaches
grep "Warning.*limit\|HighRSS\|Lowfree" /rdklogs/logs/agent.txt

# Agent restarts due to resource pressure
grep "restarting\|Selfheal\|Restart" /rdklogs/logs/agent.txt
```

### WebConfig / RBUS problems?

```bash
# WebConfig blob processing
grep -i "webconfig\|subdoc\|blob" /rdklogs/logs/ADVSEClog.txt.0

# RBUS communication errors
grep -i "rbus.*fail\|rbus.*error\|rbus_open\|Rbus Error" /rdklogs/logs/ADVSEClog.txt.0
```

### Bridge mode blocking agent?

```bash
# Check if device is in bridge mode
syscfg get bridge_mode
# "2" = bridge mode → agent will NOT run

# Look for bridge mode block in logs
grep "bridge_mode\|Bridge mode" /rdklogs/logs/agent.txt
```

### Kernel module / enforcement issues?

```bash
# Which enforcement mode?
ls /tmp/advsec_userspace_enabled /tmp/advsec_nflua_loaded

# Kernel module load failures (only relevant in nflua mode)
grep "Unable to load\|module" /rdklogs/logs/agent.txt

# iptables/ipset state
iptables -L -n | grep -i cujo
ipset list -n
```

### Root vs non-root issues?

```bash
# Check privilege mode
grep "RUNNING_AS" /rdklogs/logs/agent.txt
ls /tmp/advsec_cujo_agent_root_priv
# File exists → root; not found → non-root
```

## 3. Log Signature Reference

### Component Lifecycle

| Signature | Meaning | Source |
|-----------|---------|--------|
| `Connect to bus daemon...` | CCSP message bus engagement starting | `ssp_main.c` |
| `AdvSec Module loaded successfully...` | SSP bootstrap and DML plugin loaded | `ssp_main.c` |
| `CcspAdvSecurity: PandMDB initiated successfully` | Platform HAL DB init success | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: Failed to initiate DB` | Platform HAL DB init failure | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: modelName returned from hal:<name>` | Device model retrieved | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: firmwareVersion returned from hal:<ver>` | Firmware version retrieved | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: deviceMac [<mac>]` | MAC address successfully retrieved | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: Unable to get MACAdress or HAL not ready` | MAC retrieval failed — process will exit | `cosa_adv_security_internal.c` |
| `CcspAdvSecurity: advsec_webconfig_init` | WebConfig initialization starting | `cosa_adv_security_internal.c` |
| `NonRoot feature is enabled, dropping root privileges for cujo-agent process` | Normal privilege drop | `ssp_main.c` |
| `NonRoot feature is disabled` | cujo-agent keeping root (blocklisted) | `ssp_main.c` |
| `process[cujo-agent] is found in blocklist, thus process runs in Root mode` | Blocklist check found cujo-agent | `ssp_main.c` |

### Feature Enable/Disable

| Signature | Meaning | Source |
|-----------|---------|--------|
| `Device_Finger_Printing_enabled:false` | DeviceFingerPrint disabled at startup | `cosa_adv_security_internal.c` |
| `AdvSecUserSpace_RFCEnable:TRUE` | UserSpace RFC auto-enabled (default) | `cosa_adv_security_internal.c` |
| `AdvSecWifiDataCollection_RFCEnable:TRUE` | WiFi DCL enabled | `cosa_adv_security_internal.c` |
| `Disabling WifiDataCollection RFC` | WiFi Levl disabled at runtime → DCL teardown | `cosa_adv_security_internal.c` |
| `Unsupported parameter '<name>'` | DML handler received unknown parameter name | `cosa_adv_security_dml.c` |

### RBUS Events

| Signature | Meaning | Source |
|-----------|---------|--------|
| `AdvSecurityEventConsumer: rbus_open failed: <code>` | RBUS initialization failure | `cosa_adv_security_internal.c` |
| `AdvSecurityEventConsumer : FAILED , value is NULL` | RBUS event received with NULL value | `cosa_adv_security_internal.c` |
| `AdvSecurityEventConsumer : New value of CurrentActiveInterface is = <val>` | WAN failover event | `cosa_adv_security_internal.c` |
| `AdvSecurityEventConsumer : New value of WiFi Levl is <val>` | WiFi Levl state changed | `cosa_adv_security_internal.c` |

### WiFi Data Collection

| Signature | Meaning | Source |
|-----------|---------|--------|
| `rbus_handle is NULL` | RBUS not initialized for WiFi operations | `cosa_adv_security_internal.c` |
| `WiFi webconfig init data get SUCCESS` | WiFi DCL precheck passed | `cosa_adv_security_internal.c` |
| `WiFi webconfig init data is empty` | WiFi DCL precheck data empty | `cosa_adv_security_internal.c` |
| `Retry get WiFi webconfig init data in <n> seconds` | WiFi DCL precheck retrying | `cosa_adv_security_internal.c` |

### WebConfig Processing

| Signature | Meaning | Source |
|-----------|---------|--------|
| `entries count AnscAllocateMemory failed` | WebConfig param allocation failure | `advsecurity_param.c` |
| `process_advsecurityparams failed` | Msgpack parameter parsing failed | `advsecurity_param.c` |
| `Unknown error.` | Unrecognized WebConfig error code | `advsecurity_param.c` |

### Errors and Failures

| Signature | Meaning | Source |
|-----------|---------|--------|
| `Signal <n> received, exiting!` | Fatal signal caught (SIGSEGV, SIGBUS, etc.) | `ssp_main.c` |
| `SIGINT received!` | Interrupt signal — clean exit | `ssp_main.c` |
| `Error daemonizing (fork)!` | Fork failed during daemonization | `ssp_main.c` |
| `Exit error - cmd_dispatch failed` | Component engagement or bus connect failed | `ssp_main.c` |
| `failed to open backtrace file: /nvram/advsecssp_backtrace` | Cannot write crash trace | `ssp_main.c` |
| `syscfg_set failed` | Feature state persistence failure | `cosa_adv_security_internal.c` |
| `syscfg_commit failed` | Commit to persistent storage failed | `cosa_adv_security_internal.c` |
| `fetch safebro config failed rc = <code>` | SafeBrowsing config script error | `cosa_adv_security_internal.c` |
| `Error in opening the file.` | Cannot open SafeBrowsing JSON config | `cosa_adv_security_internal.c` |
| `json file parser error` | cJSON parse failure on SafeBrowsing config | `cosa_adv_security_internal.c` |
| `CcspBaseIf_getParameterValues <param> error <code>` | Cross-component parameter fetch failed | `cosa_adv_security_internal.c` |
| `Empty URL, go with defaults` | Partner-based URL retrieval returned empty | `cosa_adv_security_internal.c` |
| `Failed to get sysevent fd` | sysevent_open failed — process exits | `cosa_adv_security_internal.c` |
| `advsec_write_to_file failed` | Config param file write error | `cosa_adv_security_internal.c` |
| `Memory allocation failed for buffer` | malloc failure in blocklist check | `ssp_main.c` |
| `Rbus Error code:<code>` | RBUS get/set operation failure | `cosa_adv_security_internal.c` |

### Triage Pattern

1. Find first anomaly signature in logs
2. Locate nearest lifecycle event before/after
3. Map signature to function path in source code
4. Confirm whether expected next signature appears
5. Classify: initialization failure, feature activation failure, IPC failure, or resource issue

## 4. Decision Trees

### 4.1 Component Not Starting (Process Not Found)

```
Is CcspAdvSecuritySsp process running?
├─ NO
│   ├─ Check journal: journalctl -u CcspAdvSecuritySsp
│   │   ├─ "Error daemonizing (fork)!" → System resource issue
│   │   ├─ "Exit error - cmd_dispatch failed"
│   │   │   ├─ "Connect to bus daemon..." present?
│   │   │   │   ├─ NO → CCSP bus daemon not running
│   │   │   │   └─ YES → Bus connected but create/engage failed
│   │   │   │       ├─ Check TR181-AdvSecurity.xml exists
│   │   │   │       └─ Check libdmlasecurity.so exists
│   │   ├─ "Unable to get MACAdress or HAL not ready"
│   │   │   └─ Process exits after 30s → Check cm_hal, sysevent
│   │   ├─ "Signal <n> received, exiting!"
│   │   │   └─ Check /nvram/advsecssp_backtrace for stack trace
│   │   └─ No logs at all
│   │       ├─ Service enabled? → systemctl is-enabled CcspAdvSecuritySsp
│   │       └─ Binary exists? → ls -l /usr/bin/CcspAdvSecuritySsp
│   └─ Restart: systemctl restart CcspAdvSecuritySsp
└─ YES
    └─ Component registered with CR?
        ├─ NO → ssp_engage_advsec() failed
        │   └─ Check XML path and CR status
        └─ YES → Component running, check feature status (§4.2)
```

### 4.2 Feature Not Activating Despite TR-181 Set

```
DeviceFingerPrint.Enable set to true but feature not active?
├─ Is /tmp/advsec_initialized present?
│   ├─ NO
│   │   ├─ Check logs for CosaAdvSecInit() execution
│   │   ├─ Is cujo-agent binary installed?
│   │   │   ├─ NO → Agent package not installed
│   │   │   └─ YES → Check start_adv_security.sh output
│   │   └─ Bridge mode active?
│   │       ├─ YES → Features suppressed in bridge mode
│   │       └─ NO → Check shell script exit status
│   └─ YES
│       ├─ Is cujo-agent process running?
│       │   ├─ NO → Agent crashed; check agent logs + dmesg
│       │   └─ YES → Agent running but feature not behaving
│       │       ├─ Check specific feature enable (SB, SF, APC, PP)
│       │       ├─ Check RFC toggle for the feature
│       │       └─ Verify syscfg value matches runtime state
│       └─ Feature-specific check:
│           ├─ SafeBrowsing: requires DeviceFingerPrint + SB_RFC
│           ├─ Softflowd: requires DeviceFingerPrint
│           ├─ ParentalControl: requires DeviceFingerPrint + APC_RFC
│           └─ PrivacyProtection: requires DeviceFingerPrint + PP_RFC
```

### 4.3 WebConfig Blob Rejected

```
WebConfig blob for "advsecurity" failed?
├─ Check blob version
│   ├─ Version <= current → Stale blob, skip expected
│   └─ Version > current
│       ├─ Decode error?
│       │   ├─ "entries count AnscAllocateMemory failed" → OOM
│       │   ├─ "process_advsecurityparams failed" → Malformed msgpack
│       │   └─ "Invalid first element" → Wrong wrapper format
│       ├─ Processing error?
│       │   ├─ Check which feature failed to apply
│       │   ├─ Rollback triggered? → Check rollback logs
│       │   └─ syscfg_set failure? → Storage full
│       └─ Success but features not active?
│           └─ Check DeviceFingerPrint as prerequisite
```

### 4.4 Security Agent Not Responding

```
cujo-agent not responding?
├─ Process exists?
│   ├─ NO → Crashed or was killed
│   │   ├─ Check dmesg for OOM killer
│   │   ├─ Check /tmp/advsec_cujo_agent_root_priv
│   │   │   ├─ Exists → Agent ran as root (blocklisted)
│   │   │   └─ Not exists → Agent ran as non-root
│   │   └─ Check advsec_cpu_mem_recovery.sh logs
│   └─ YES → Process alive
│       ├─ High CPU? → Recovery script may restart it
│       ├─ Check socket connectivity
│       ├─ Check kernel modules loaded
│       │   ├─ lsmod | grep nflua
│       │   └─ lsmod | grep luaconntrack
│       └─ Check iptables rules present
│           └─ iptables -L | grep cujo
```

### 4.5 High CPU/Memory from Security Features

```
High resource usage?
├─ Identify process: top -bn1 | grep -E 'CcspAdvSec|cujo-agent|nflua'
├─ CcspAdvSecuritySsp high CPU?
│   ├─ Check logger thread period (too frequent?)
│   ├─ Check sysevent handler spinning
│   └─ Restart: systemctl restart CcspAdvSecuritySsp
├─ cujo-agent high CPU?
│   ├─ advsec_cpu_mem_recovery.sh should handle
│   ├─ Check soft/hard memory limits
│   ├─ Check RabidFramework.MemoryLimit value
│   └─ Disable non-essential features temporarily
└─ nflua high memory?
    ├─ Check: cat /proc/nflua/memory
    └─ May need kernel module reload
```

### 4.6 SafeBrowsing Lookups Failing

```
SafeBrowsing lookups timing out?
├─ Check LookupTimeout value
│   ├─ Too low? → Increase via TR-181
│   └─ Reasonable? → Network issue
├─ Check LookupTimeoutExceededCount
│   └─ cat /tmp/advsec_lkup_exceed_cnt
├─ Check endpoint URL
│   ├─ Custom URL set? → Verify accessibility
│   └─ Default URL → Check partner URL retrieval
├─ SafeBrowsing config valid?
│   ├─ cat /tmp/safebro.json
│   └─ Check cJSON parse in logs
└─ DNS resolution working?
    └─ nslookup <endpoint_host>
```

## 5. Diagnostic Commands

```bash
# Process status
ps | grep -i CcspAdvSecuritySsp | grep -v grep
ps | grep cujo-agent | grep -v grep

# Service management
systemctl status CcspAdvSecuritySsp
systemctl restart CcspAdvSecuritySsp

# Component logs
journalctl -u CcspAdvSecuritySsp -n 300 --no-pager

# Feature states via dmcli
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.Enable
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.Enable
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedParentalControl.Activate
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_PrivacyProtection.Activate

# Init markers
ls -la /tmp/advsec_initialized
ls -la /tmp/advsec_config_params/
ls -la /tmp/advsec_ccsp_initialized_bootup

# Kernel modules
lsmod | grep -E 'nflua|luaconntrack'

# Resource usage
top -bn1 | grep -E 'CcspAdvSec|cujo-agent'

# Crash backtrace
cat /nvram/advsecssp_backtrace 2>/dev/null

# syscfg values
syscfg get Advsecurity_DeviceFingerPrint
syscfg get Advsecurity_SafeBrowsing
syscfg get Advsecurity_Softflowd
syscfg get Adv_PCActivate
syscfg get Adv_PPActivate
```
