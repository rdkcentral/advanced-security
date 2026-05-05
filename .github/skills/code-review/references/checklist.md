# Code Review Checklist — CcspAdvSecurity

## Quick Assessment (5 min)

### Risk Scoring (1-5 each, total ≥15 = senior reviewer)

| Dimension | Score |
|-----------|-------|
| Scope (lines/files) | _/5 |
| Criticality (Internal/DML=5, tests=1) | _/5 |
| Complexity (single func=2, cross-module=4) | _/5 |
| Safety (no alloc=1, ownership transfers=5) | _/5 |
| Test Coverage (comprehensive=1, none=5) | _/5 |
| **Total** | **_/25** |

**Risk levels:** ≤8 LOW → 9-14 MEDIUM → 15-19 HIGH → ≥20 CRITICAL

### Module Risk Map

| Module | Path | Base Risk |
|--------|------|-----------|
| Internal Lifecycle | `cosa_adv_security_internal.*` | HIGH |
| DML Handlers | `cosa_adv_security_dml.*` | HIGH |
| WebConfig | `cosa_adv_security_webconfig.*` | MEDIUM-HIGH |
| Plugin | `plugin_main.*` | MEDIUM |
| Helpers/Param | `advsecurity_helpers.*`, `advsecurity_param.*` | MEDIUM |
| SSP Daemon | `source/AdvSecuritySsp/*` | MEDIUM |
| Scripts | `scripts/*` | MEDIUM |
| Tests | `source/test/*` | LOW |

---

## Full Checklist

### General
- [ ] No warnings (`-Wall -Werror`)
- [ ] No unrelated formatting mixed with logic
- [ ] PR explains the **why**
- [ ] Single concern per change

### Memory Safety
- [ ] Every `AnscAllocateMemory`/`malloc`/`calloc`/`strdup` checked for NULL within 3 lines
- [ ] Every allocation has matching `AnscFreeMemory`/`free` on all paths including errors
- [ ] No use-after-free; pointers NULL'd after free in long-lived contexts
- [ ] No double-free; `goto cleanup` patterns free only once
- [ ] `snprintf` instead of `sprintf`/`strcpy`; buffer lengths include null terminator
- [ ] `g_pAdvSecAgent` checked for NULL before member access
- [ ] Nested COSA struct allocations freed in correct order in `CosaSecurityRemove`

### Thread Safety
- [ ] `logMutex` balanced lock/unlock on all paths
- [ ] No blocking I/O (`v_secure_system`) under `logMutex`
- [ ] Logger thread shutdown properly coordinated
- [ ] Sysevent handler thread checks shutdown flag

- [ ] `pthread_create` return checked
- [ ] No TOCTOU races on `g_pAdvSecAgent` state

### Security
- [ ] URL inputs validated via `isValidUrl()` before use
- [ ] Non-HTTPS URLs rejected
- [ ] No raw `system()` calls — use `v_secure_system()`
- [ ] No command injection via string concatenation to shell
- [ ] No sensitive data logged (subscriber IDs, MACs at INFO)

### Feature Lifecycle
- [ ] Init/DeInit functions are symmetric
- [ ] syscfg key matches existing naming pattern (`Adv_*`, `Advsecurity_*`)
- [ ] Script flag matches `start_adv_security.sh` handler
- [ ] Sentinel files created/cleaned properly
- [ ] Dependencies documented (e.g., UserSpace required for SB-RFC)
- [ ] SafeBrowsing/Softflowd V/C/R remain NO-OPs

### Error Handling
- [ ] All return values checked
- [ ] Error paths log: function name, error code, relevant params
- [ ] Error codes distinguish failure modes
- [ ] Partial init rolled back on failure

### API & Platform
- [ ] TR-181 parameters validated in DML handlers
- [ ] Platform guards (`#ifdef _COSA_BCM_MIPS_`, etc.) correctly placed
- [ ] New sources in `Makefile.am`; new deps in `configure.ac`
- [ ] DML handler registered in `plugin_main.c` if new

### Testing
- [ ] New functions have tests; modified functions have updated coverage
- [ ] Edge cases: NULL g_pAdvSecAgent, bridge mode, concurrent calls
- [ ] Negative test cases for error paths
- [ ] Mock expectations verified

---

## Priority Flags

| Priority | Criteria | Action |
|----------|----------|--------|
| 🔴 MUST FIX | Leak/crash, race, raw system(), URL injection, security | Block merge |
| 🟡 SHOULD FIX | Error handling gap, missing validation, test gap | Fix before merge preferred |
| 🔵 CONSIDER | Style, docs, minor improvement | Optional |
