---
applyTo: "**/*.c,**/*.h"
---

# C Programming Standards for CcspAdvSecurity Embedded Systems

## Memory Management

### Allocation Rules
- **Prefer stack allocation** for fixed-size, short-lived data
- **Use AnscAllocateMemory/malloc** only when necessary; always pair with AnscFreeMemory/free
- **Check all allocations**: Never assume allocation succeeds
- **Free in reverse order** of allocation to reduce fragmentation
- **NULL pointers after free** to catch use-after-free in debug builds

```c
// GOOD: Checked heap allocation with cleanup
PCOSA_DATAMODEL_AGENT pAgent = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
if (!pAgent) {
    CcspTraceError(("%s: Failed to allocate COSA_DATAMODEL_AGENT\n", __FUNCTION__));
    return NULL;
}
memset(pAgent, 0, sizeof(COSA_DATAMODEL_AGENT));
// ... use pAgent ...
AnscFreeMemory(pAgent);
pAgent = NULL;

// BAD: Unchecked allocation
PCOSA_DATAMODEL_AGENT pAgent = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
pAgent->bEnable = TRUE;  // Crash if allocation failed
```

### Memory Leak Prevention
- Every function that allocates must document ownership transfer
- Use goto for single exit point in complex error handling
- Implement cleanup functions for complex structures

```c
// GOOD: Single exit point with cleanup (pattern from CosaSecurityCreate)
ANSC_HANDLE CosaSecurityCreate(void) {
    PCOSA_DATAMODEL_AGENT pAgent = NULL;
    PCOSA_DATAMODEL_ADVSEC pAdvSec = NULL;
    PCOSA_DATAMODEL_SB pSafeBrows = NULL;

    pAgent = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
    if (!pAgent) goto cleanup;

    pAdvSec = (PCOSA_DATAMODEL_ADVSEC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!pAdvSec) goto cleanup;

    pSafeBrows = (PCOSA_DATAMODEL_SB)AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
    if (!pSafeBrows) goto cleanup;

    pAgent->pAdvSec = pAdvSec;
    pAdvSec->pSafeBrows = pSafeBrows;
    return (ANSC_HANDLE)pAgent;

cleanup:
    AnscFreeMemory(pSafeBrows);
    AnscFreeMemory(pAdvSec);
    AnscFreeMemory(pAgent);
    return NULL;
}
```

## Resource Constraints

### CPU Optimization
- Minimize system calls in hot paths (feature status checks)
- Cache frequently accessed data (feature enable/disable state in COSA structs)
- Use `v_secure_system()` instead of `system()` — it is both safer and optimized

### Memory Optimization
- Use BOOL for boolean flags in data model structures
- Use const for read-only data (goes in .rodata)
- Prefer static buffers with known bounds for syscfg values

```c
// GOOD: Fixed-size buffer for syscfg reads
char value[MAX_VALUE];
memset(value, 0, sizeof(value));
if (0 == syscfg_get(NULL, g_DeviceFingerPrintEnabled, value, sizeof(value))) {
    Value = atoi(value);
}
```

## Platform Independence

### Never Assume
- Platform type (use `#ifdef _COSA_BCM_MIPS_`, `_COSA_INTEL_XB3_ARM_` guards)
- Pointer size (use uintptr_t for pointer arithmetic)
- Integer sizes (use int32_t, uint64_t from stdint.h)
- Vendor name (use CONFIG_VENDOR_NAME macro)

```c
// GOOD: Platform-specific headers behind #ifdef
#if defined(_COSA_BCM_MIPS_)
#include <ccsp/dpoe_hal.h>
#else
#include <ccsp/cm_hal.h>
#endif
```

## Error Handling

### Return Value Convention
- Return `ANSC_STATUS_SUCCESS` / `ANSC_STATUS_FAILURE` for ANSC functions
- Return `RETURN_OK` / `RETURN_ERROR` for internal functions
- Return `TRUE` / `FALSE` for DML Get/Set handlers
- Preserve error context in logs — never discard failure reasons

```c
// GOOD: DML handler with proper logging
BOOL SafeBrowsing_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    UNREFERENCED_PARAMETER(hInsContext);
    if (strcmp(ParamName, "Enable") == 0) {
        if (bValue) {
            CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING);
        } else {
            CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING);
        }
        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}
```

### Logging
- Use severity levels appropriately
- Log feature state transitions with before/after context
- Never log at ERROR for expected conditions (bridge mode skip)

```c
// GOOD: Feature state logging
CcspTraceInfo(("AdvSec: Feature %s %s (syscfg=%s)\n",
    feature_name, bEnable ? "ENABLED" : "DISABLED", syscfg_key));
```

## Security

### Input Validation
- All URL inputs must pass `isValidUrl()` before use
- Reject non-HTTPS URLs
- Check for command injection characters: `;`, `&`, `|`, `'`

```c
// GOOD: URL validation before use
if (isValidUrl(pInputUrl) != ANSC_STATUS_SUCCESS) {
    CcspTraceError(("%s: Invalid URL rejected\n", __FUNCTION__));
    return FALSE;
}
```

### Shell Invocation
- Always use `v_secure_system()` — never raw `system()`
- Never concatenate user input into shell commands

```c
// GOOD: Safe shell invocation
v_secure_system("start_adv_security.sh -enable");

// BAD: Command injection risk
char cmd[256];
sprintf(cmd, "start_adv_security.sh %s", user_input);
system(cmd);
```
