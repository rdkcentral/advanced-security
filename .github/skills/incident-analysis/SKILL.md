---
name: incident-analysis
description: "Triage any CcspAdvSecurity behavioral issue by correlating device logs with source code and build a production-grade RCA with hypothesis scoring."
---

# Incident Analysis Skill

Systematically correlate device log bundles with CcspAdvSecurity source code to identify root causes, characterize impact, and produce RCA reports with confidence-scored hypotheses.

## When to Use

- Device log bundle available with a security feature behavioral anomaly
- Need to classify failure domain and blast radius
- Need confidence-scored hypotheses and disproof checks
- Need fix and test recommendations for engineering review

---

## Step 1: Orient to Log Bundle

```
logs/<MAC>/<SESSION_TIMESTAMP>/logs/
    ADVSEClog.txt.0                  ← Primary (start here)
    CujoAgentLog.txt.0               ← cujo-agent runtime
    SelfHeal*.txt.0                  ← Watchdog/recovery
    top_log.txt.0                    ← CPU/memory
    messages.txt.0                   ← Kernel/system
    syscfg.db                        ← Persistent config state
```

Timestamp format: `YYMMDD-HH:MM:SS.uuuuuu`

## Step 2: Map Feature State and Threads

Read startup of `ADVSEClog.txt.0` (first ~50 lines):

| Pattern | Meaning |
|---------|---------|
| `Initializing CosaAdvSecurityAgent` | Agent startup |
| `Advanced Security : ${CUJO_AGENT_LOG} is installed` | Agent binary found |
| `Advanced Security : Device is in Bridge Mode` | Bridge mode — agent skipped |
| `Advanced Security Service is already being initialized` | Re-entrant init blocked |
| `CosaAdvSecInit` | DeviceFingerPrint enabling |
| `CosaAdvSecStartFeatures` | SafeBrowsing/Softflowd starting |

Thread roles: Main (SSP daemon, bus registration), Logger (`advsec_logger_th`), Sysevent Handler (`advsec_sysevent_handler_th`).

## Step 3: Identify Anomaly Window

Based on user's stated issue, search for relevant evidence:

| Issue | Search | Anomaly Signal |
|-------|--------|---------------|
| Feature not activating | `grep "CosaAdvSecInit\|CosaAdvSecStartFeatures\|start_adv_security"` | Missing or error |
| Agent not starting | `grep "installed\|not installed\|Bridge Mode"` | Not installed or bridge mode |
| RFC toggle ignored | `grep "Init\|DeInit\|RFC"` | Init not called after set |
| SafeBrowsing broken | `grep "SafeBrowsing\|safebro\|LookupTimeout"` | Config error or timeout |
| Feature cycling | `grep "enable\|disable\|start\|stop"` | Repeated enable/disable |
| syscfg mismatch | `grep "syscfg_get\|syscfg_set\|CosaGetSysCfgUlong"` | Get/set failures |

## Step 4: Correlate with Companion Logs

| Issue | Log | Look For |
|-------|-----|----------|
| Agent crash | `messages.txt.0` | Segfault, SIGSEGV, core dump |
| cujo-agent failure | `CujoAgentLog.txt.0` | Agent process errors |
| Resource exhaustion | `top_log.txt.0` | CPU%, memory at anomaly time |
| Watchdog restart | `SelfHeal*.txt.0` | Health check failures |
| Config state | `syscfg.db` | Verify persistent key values |

## Step 5: Locate Code Path

| Module | Path | Covers |
|--------|------|--------|
| DML Handlers | `cosa_adv_security_dml.c` | TR-181 Get/Set handlers |
| Internal Lifecycle | `cosa_adv_security_internal.c` | Init/DeInit, syscfg, scripts, threads |
| WebConfig | `cosa_adv_security_webconfig.c` | Blob processing |
| Plugin | `plugin_main.c` | Registration, create/destroy |
| SSP Main | `ssp_main.c` | Daemon startup, signals |
| Agent Script | `start_adv_security.sh` | cujo-agent lifecycle |
| Environment | `advsec.sh` | Paths, sentinel files, modules |

## Step 6: Characterize Root Cause

Assign confidence: 80-100% = direct log + code corroboration, 50-79% = strong circumstantial, <50% = hypothesis only.

## Step 7: Build RCA Report

### Evidence Matrix (≥5 items)
| Evidence | Source | Inference | Confidence |
|----------|--------|-----------|------------|

### Hypotheses (≥2)
- H1 primary (confidence %)
- H2 alternate (confidence %)

Each with: supporting evidence, disproof checks, what would increase confidence.

### Root Cause Decision
One of: confirmed | probable (insufficient evidence) | not yet determinable

### Fix + Validation
1. Minimal fix direction (function-level)
2. L1 unit test addition
3. L2 functional scenario (Gherkin outline)
4. Rollback/containment plan

## Quality Bar

- ≥1 feature lifecycle log evidence item
- ≥1 syscfg state evidence item
- ≥1 negative/disproof check
- Don't conflate agent not installed with agent crash
- Don't confuse RFC toggle with feature activation
- Don't assume bridge mode without checking syscfg `bridge_mode`

## Common Pitfalls

- SafeBrowsing Validate/Commit are NO-OPs — actual logic in SetParamBoolValue
- UserSpace RFC DeInit is commented out — cannot be disabled
- Raptr RFC is enable-only — disable returns FALSE
- AdvSecSafeBrowsing_RFC and CujoTelemetryWiFiFP_RFC require UserSpace_RFC
- Multiple sentinel files may conflict if not properly cleaned up
