# First 30 Minutes: Advanced Security Onboarding

This guide gets a new engineer from zero context to productive debugging in 30 minutes.

## Outcome

By the end, you should be able to:

1. Explain the plugin-based architecture and how TR-181 objects map to DML handler functions.
2. Map source files to responsibilities (SSP, DML plugin, WebConfig, scripts, agent).
3. Identify all security feature modules and their RFC toggle dependencies.
4. Run first-line diagnostics for security feature issues.
5. Triage a feature activation or WebConfig failure with evidence.

## Minute 0-5: Build the Mental Model

Read in this order:

1. [architecture.md](architecture.md)
2. [workflows.md](workflows.md)
3. [developer-playbook.md](developer-playbook.md)

Memorize the component's layered structure:

```
SSP Bootstrap → CCSP Bus → Plugin Load → DML Registration → Feature Init → Shell Scripts → cujo-agent
```

Key concept: CcspAdvSecuritySsp is the **management interface** — it does NOT perform security enforcement itself. It configures and controls the external `cujo-agent` process via shell scripts.

## Minute 5-10: Map Files to Responsibilities

| Responsibility | File |
|---------------|------|
| Daemon bootstrap, privilege drop, signals | `source/AdvSecuritySsp/ssp_main.c` |
| Component registration with CR | `source/AdvSecuritySsp/ssp_action.c` |
| Message bus engagement | `source/AdvSecuritySsp/ssp_messagebus_interface.c` |
| Plugin entry, DML function registration | `source/AdvSecurityDml/plugin_main.c` |
| TR-181 Get/Set/Validate/Commit/Rollback | `source/AdvSecurityDml/cosa_adv_security_dml.c` |
| Lifecycle: Create/Initialize/Remove | `source/AdvSecurityDml/cosa_adv_security_internal.c` |
| Feature data model structs, Init/DeInit decl | `source/AdvSecurityDml/cosa_adv_security_internal.h` |
| WebConfig blob handling | `source/AdvSecurityDml/cosa_adv_security_webconfig.c` |
| Msgpack decode for WebConfig | `source/AdvSecurityDml/advsecurity_param.c` |
| WiFi Data Collection consumer | `source/AdvSecurityDml/cujoagent_dcl_api.c` |
| Agent start/stop, feature control | `scripts/advsec.sh` |
| Feature-level enable/disable | `scripts/start_adv_security.sh` |
| CPU/memory recovery | `scripts/advsec_cpu_mem_recovery.sh` |
| Telemetry status logging | `scripts/advsec_log_fp_status.sh` |
| TR-181 data model definition | `config/TR181-AdvSecurity.xml` |

## Minute 10-15: Learn Critical Log Signatures

Must recognize these immediately:

- `AdvSec Module loaded successfully...` — Component fully started
- `CcspAdvSecurity: PandMDB initiated successfully` — HAL DB ready
- `CcspAdvSecurity: deviceMac [xx:xx:xx:xx:xx:xx]` — MAC acquired
- `CcspAdvSecurity: Unable to get MACAdress or HAL not ready` — Fatal: process will exit
- `AdvSecurityEventConsumer: rbus_open failed` — RBUS failure, blocks features
- `Device_Finger_Printing_enabled:false` — Core feature disabled at startup
- `syscfg_set failed` / `syscfg_commit failed` — Persistence error
- `Signal <n> received, exiting!` — Crash with stack trace
- `Exit error - cmd_dispatch failed` — Bus or SSP creation failure

Reference: [troubleshooting.md § Log Signatures](troubleshooting.md#3-log-signature-reference)

## Minute 15-20: Run First-Line Diagnostics

```bash
# Is the component running?
ps | grep -i CcspAdvSecuritySsp | grep -v grep

# Is the agent running?
ps | grep cujo-agent | grep -v grep

# Check recent logs
journalctl -u CcspAdvSecuritySsp -n 120 --no-pager

# Check core feature state
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable

# Check init markers
ls -la /tmp/advsec_initialized
ls -la /tmp/advsec_config_params/

# Check enforcement mode (nflua vs userspace)
ls /tmp/advsec_userspace_enabled
# File exists → userspace mode (most modern devices)
ls /tmp/advsec_nflua_loaded
# File exists → kernel (nflua) mode (legacy devices)
# Only one of these should exist at a time

# If kernel mode, verify kernel modules
lsmod | grep -E 'nflua|luaconntrack'

# Check resource usage
top -bn1 | grep -E 'CcspAdvSec|cujo-agent'
```

## Minute 20-25: Validate Feature Activation

Step-by-step: enable DeviceFingerPrint and verify end-to-end.

```bash
# 1. Enable
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable bool true

# 2. Check TR-181 value
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable
# Expected: value = true

# 3. Check syscfg persistence
syscfg get Advsecurity_DeviceFingerPrint
# Expected: 1

# 4. Check init marker
ls -l /tmp/advsec_initialized
# Expected: file exists

# 5. Check agent started
ps | grep cujo-agent | grep -v grep
# Expected: process running

# 6. Check config params delivered
for f in MODEL MANUFACTURER FWVER HWVER CMMAC; do
    echo "$f: $(cat /tmp/advsec_config_params/$f 2>/dev/null)"
done
# Expected: all files have values
```

## Minute 25-30: Complete One Triage Drill

Use this scenario: **SafeBrowsing fails to activate after TR-181 set.**

1. Check DeviceFingerPrint is enabled (prerequisite):
   ```bash
   dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable
   ```

2. Check SafeBrowsing state:
   ```bash
   dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.Enable
   syscfg get Advsecurity_SafeBrowsing
   ```

3. Check SafeBrowsing RFC toggle:
   ```bash
   syscfg get Adv_AdvSecSafeBrowsingRFCEnable
   ```

4. Check logs for SafeBrowsing activation:
   ```bash
   grep -i 'SafeBrowsing\|startSB\|stopSB' /rdklogs/logs/ADVSEClog.txt.0
   ```

5. Check shell script execution:
   ```bash
   grep -i 'safebro\|SafeBrowsing' /rdklogs/logs/advsec_start.log 2>/dev/null
   ```

6. Formulate hypothesis: e.g., "SafeBrowsing RFC is disabled (syscfg Adv_AdvSecSafeBrowsingRFCEnable = 0), so SafeBrowsing_SetParamBoolValue returns success but the feature does not activate in the agent."

Then run the formal triage workflow: [troubleshooting.md](troubleshooting.md)

## What Good Looks Like

A good first triage note includes:

1. Exact timeline with timestamps from logs.
2. Feature states observed (TR-181 values + syscfg values).
3. Which Init/DeInit function was called (or not called).
4. Root-cause hypothesis with confidence level.
5. Next validation step to confirm or disprove.
