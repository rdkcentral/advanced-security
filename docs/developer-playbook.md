# Advanced Security Developer Playbook

This playbook provides practical commands and validation steps for local debugging, feature testing, and incident triage.

See [architecture.md](architecture.md) for system design and [troubleshooting.md](troubleshooting.md) for decision trees.

## 1. Process and Service Control

```bash
# Process check
ps | grep -i CcspAdvSecuritySsp | grep -v grep

# Agent process check
ps | grep cujo-agent | grep -v grep

# Systemd status
systemctl status CcspAdvSecuritySsp

# Restart component
systemctl restart CcspAdvSecuritySsp

# Start/stop agent manually
/usr/ccsp/advsec/advsec.sh -start
/usr/ccsp/advsec/advsec.sh -stop
```

## 2. Logs and Trace Collection

```bash
# Component journal logs
journalctl -u CcspAdvSecuritySsp -n 300 --no-pager

# CCSP trace log (platform-specific path)
tail -n 300 /rdklogs/logs/ADVSEClog.txt.0

# Grep for key lifecycle events
grep -Ei 'Module loaded|PandMDB|deviceMac|advsec_webconfig|DeviceFingerPrint|EXIT Error' \
    /rdklogs/logs/ADVSEClog.txt.0

# Grep for feature enable/disable
grep -Ei 'RFCEnable|enabled:false|enabled:true|Init|DeInit' \
    /rdklogs/logs/ADVSEClog.txt.0

# Script execution logs
cat /rdklogs/logs/advsec_start.log 2>/dev/null

# Agent logs
ls -la /tmp/advsec/log/ 2>/dev/null
ls -la /var/log/cujo/ 2>/dev/null

# Crash backtrace
cat /nvram/advsecssp_backtrace 2>/dev/null

# Kernel module messages
dmesg | grep -iE 'nflua|luaconntrack|cujo'
```

## 3. TR-181 Parameter Validation

### Core Feature Parameters

```bash
# DeviceFingerPrint
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.LoggingPeriod
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.LogLevel
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.EndpointURL

# SafeBrowsing
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.Enable
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.LookupTimeout
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.LookupTimeoutExceededCount

# Softflowd
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.Enable

# Advanced Parental Control
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedParentalControl.Activate

# Privacy Protection
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_PrivacyProtection.Activate
```

### RFC Toggle Parameters

```bash
# All RFC feature toggles
for rfc in AdvancedParentalControl PrivacyProtection DeviceFingerPrintICMPv6 \
           WS-Discovery_Analysis AdvancedSecurityOTM AdvanceSecurityUserSpace \
           AdvanceSecurityCujoTracer AdvanceSecurityCujoTelemetry \
           AdvSecSentryAtTheEdge AdvSecTCPTrackerFilterDevices; do
    echo "--- $rfc ---"
    dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.$rfc.Enable
done
```

### RabidFramework Parameters

```bash
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.MemoryLimit
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.MacCacheSize
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.DNSCacheSize
```

### Set Feature Parameters

```bash
# Enable DeviceFingerPrint
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable bool true

# Enable SafeBrowsing
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.Enable bool true

# Set SafeBrowsing LookupTimeout (ms)
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.LookupTimeout uint 5000

# Set logging period (seconds)
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.LoggingPeriod uint 3600
```

## 4. Security Agent Status Checks

```bash
# Agent process
ps | grep cujo-agent | grep -v grep

# Agent running as root or non-root?
ls -l /tmp/advsec_cujo_agent_root_priv 2>/dev/null
# If file exists → running as root (blocklisted)
grep -i "RUNNING_AS" /rdklogs/logs/agent.txt
# CUJO_AGENT_RUNNING_AS_NON_ROOT or CUJO_AGENT_RUNNING_AS_ROOT

# Enforcement mode check
ls /tmp/advsec_userspace_enabled
# File exists → userspace mode (agent handles traffic in its own process)
ls /tmp/advsec_nflua_loaded
# File exists → kernel (nflua) mode (Lua scripts in kernel netfilter)

# Verify via syscfg
syscfg get Adv_AdvSecUserSpaceRFCEnable
# 1 → userspace mode; 0 or empty → kernel mode

# If kernel mode, verify kernel modules
lsmod | grep -E 'nflua|luaconntrack'

# IPset rules
ipset list | head -n 20

# iptables rules related to cujo
iptables -L -n 2>/dev/null | grep -i cujo
ip6tables -L -n 2>/dev/null | grep -i cujo

# Agent runtime directory and PID
ls -la /tmp/cujo-agent.pid
cat /tmp/cujo-agent.pid

# Agent sockets
ls -la /tmp/*.sock
netstat -ln | grep cujo
# WiFi data collection socket (non-root: /tmp/wifi.sock)
ls -la /tmp/wifi.sock
```

## 5. WebConfig Diagnostics

```bash
# Check if WebConfig is initialized
ls -l /tmp/advsec_initialized

# SafeBrowsing config JSON
cat /tmp/safebro.json 2>/dev/null | python3 -m json.tool 2>/dev/null || cat /tmp/safebro.json

# Manually invoke SafeBrowsing config fetch
/usr/ccsp/advsec/start_adv_security.sh -getSafebroConfig
```

## 6. Feature Toggle Debugging (End-to-End)

Step-by-step to enable DeviceFingerPrint and verify:

```bash
# 1. Enable the feature
dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable bool true

# 2. Verify TR-181 value persisted
dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.Enable
syscfg get Advsecurity_DeviceFingerPrint
# Expected: both return "1" or "true"

# 3. Check init marker
ls -l /tmp/advsec_initialized
# Expected: file exists

# 4. Verify agent started
ps | grep cujo-agent | grep -v grep
# Expected: cujo-agent process present

# 5. Check kernel modules loaded
lsmod | grep nflua
# Expected: nflua module loaded

# 6. Check config params
for f in MODEL MANUFACTURER FWVER HWVER CMMAC; do
    echo "$f: $(cat /tmp/advsec_config_params/$f 2>/dev/null)"
done
```

## 7. Script Execution and Debugging

```bash
# Run advsec.sh with debug
bash -x /usr/ccsp/advsec/advsec.sh -start

# Run start_adv_security.sh with debug
bash -x /usr/ccsp/advsec/start_adv_security.sh -enable

# Feature-specific script operations
/usr/ccsp/advsec/start_adv_security.sh -start sb null  # Start SafeBrowsing
/usr/ccsp/advsec/start_adv_security.sh -stop sb null   # Stop SafeBrowsing
/usr/ccsp/advsec/start_adv_security.sh -start null sf  # Start Softflowd
/usr/ccsp/advsec/start_adv_security.sh -stop null sf   # Stop Softflowd
/usr/ccsp/advsec/start_adv_security.sh -startAdvPC     # Start Parental Control
/usr/ccsp/advsec/start_adv_security.sh -stopAdvPC      # Stop Parental Control
/usr/ccsp/advsec/start_adv_security.sh -startPrivProt  # Start Privacy Protection
/usr/ccsp/advsec/start_adv_security.sh -stopPrivProt   # Stop Privacy Protection

# CPU/memory recovery (manual run with debug)
bash -x /usr/ccsp/advsec/advsec_cpu_mem_recovery.sh

# Telemetry/status check (manual run)
bash -x /usr/ccsp/advsec/advsec_log_fp_status.sh
```

## 8. Build and Test

```bash
# Full build
./autogen.sh
./configure
make

# Build with unit test support
./autogen.sh
./configure --enable-unitTestDockerSupport
make

# Build with WiFi DCL
./configure --enable-wifidcl

# Build for specific architecture
./configure --with-ccsp-arch=arm

# Run unit tests
make -C source/test
source/test/run_ut.sh

# Run tests directly
./source/test/CcspAdvSecurityDmlTest/CcspAdvSecurityDmlTest_gtest.bin
```

## 9. Resource Monitoring

```bash
# CPU and memory snapshot
top -bn1 | grep -E 'CcspAdvSec|cujo-agent|nflua'

# Detailed memory
ps -o pid,vsz,rss,comm -p $(pgrep CcspAdvSecuritySsp) 2>/dev/null
ps -o pid,vsz,rss,comm -p $(pgrep cujo-agent) 2>/dev/null

# nflua memory (if module loaded)
cat /proc/nflua/memory 2>/dev/null

# System memory
free -m
cat /proc/meminfo | head -n 10
```

## 10. Syscfg and Persistence Inspection

```bash
# Core feature states
syscfg get Advsecurity_DeviceFingerPrint
syscfg get Advsecurity_SafeBrowsing
syscfg get Advsecurity_Softflowd
syscfg get Adv_PCActivate
syscfg get Adv_PPActivate

# Logging config
syscfg get Advsecurity_LoggingPeriod
syscfg get Advsecurity_LogLevel
syscfg get Advsecurity_LookupTimeout

# Endpoint URLs
syscfg get Advsecurity_CustomEndpointURL
syscfg get Advsecurity_DefaultEndpointURL

# Rabid framework
syscfg get Advsecurity_RabidMemoryLimit
syscfg get Advsecurity_RabidMacCacheSize
syscfg get Advsecurity_RabidDNSCacheSize

# RFC flags
for key in Adv_PCRFCEnable Adv_PrivProtRFCEnable Adv_DFICMPv6RFCEnable \
           Adv_WSDisAnaRFCEnable Adv_AdvSecOTMRFCEnable Adv_AdvSecUserSpaceRFCEnable \
           Adv_RaptrRFCEnable Adv_AdvSecAgentRFCEnable Adv_AdvSecSafeBrowsingRFCEnable \
           Adv_AdvSecCujoTelemetryWiFiFPRFCEnable Adv_AdvSecCujoTracerRFCEnable \
           Adv_AdvSecCujoTelemetryRFCEnable Adv_SATERFCEnable \
           Adv_TCPTrackerFilterDevicesRFCEnable; do
    echo "$key=$(syscfg get $key)"
done
```
