# Common Pitfalls — CcspAdvSecurity

This document catalogues recurring coding mistakes in the CcspAdvSecurity codebase.
Each pitfall includes a **WRONG** example, the **Consequence**, and the **CORRECT** pattern.

---

## 1. Unchecked COSA Struct Allocation

**WRONG:**
```c
PCOSA_DATAMODEL_SB pSB = AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
pSB->bEnable = FALSE;  // crash if AnscAllocateMemory returns NULL
```

**Consequence:** NULL dereference on memory-constrained embedded targets.

**CORRECT:**
```c
PCOSA_DATAMODEL_SB pSB = AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
if (pSB == NULL) {
    CcspTraceError(("%s: AnscAllocateMemory failed for SafeBrowsing\n", __FUNCTION__));
    return NULL;
}
memset(pSB, 0, sizeof(COSA_DATAMODEL_SB));
```

---

## 2. Assuming SafeBrowsing Validate/Commit Do Work

**WRONG:**
```c
// Developer adds validation logic to SafeBrowsing_Validate
BOOL SafeBrowsing_Validate(ANSC_HANDLE hInsContext, char* pReturnParamName, ULONG* puLength)
{
    // Check if SafeBrowsing can be enabled...
    if (!canEnable) return FALSE;
    return TRUE;
}
```

**Consequence:** Validate/Commit/Rollback are registered but are NO-OPs. All actual enable/disable logic happens in `SafeBrowsing_SetParamBoolValue`. Adding logic here creates a false sense of validation.

**CORRECT:**
```c
// Keep Validate/Commit/Rollback as NO-OPs per design
BOOL SafeBrowsing_Validate(...) { return TRUE; }
BOOL SafeBrowsing_Commit(...) { return ANSC_STATUS_SUCCESS; }
BOOL SafeBrowsing_Rollback(...) { return ANSC_STATUS_SUCCESS; }

// All logic belongs in SetParamBoolValue
BOOL SafeBrowsing_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue)
{
    if (strcmp(ParamName, "Enable") == 0) {
        if (bValue) CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING);
        else CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING);
        return TRUE;
    }
    return FALSE;
}
```

---

## 3. Using system() Instead of v_secure_system()

**WRONG:**
```c
char cmd[256];
snprintf(cmd, sizeof(cmd), "start_adv_security.sh -enable");
system(cmd);
```

**Consequence:** Security vulnerability — `system()` is susceptible to shell injection. Also violates project coding standards.

**CORRECT:**
```c
v_secure_system("start_adv_security.sh -enable");
```

---

## 4. Missing URL Validation Before Shell Use

**WRONG:**
```c
BOOL DeviceFingerPrint_SetParamStringValue(... char* pString)
{
    if (strcmp(ParamName, "RedirectorURL") == 0) {
        // Store URL directly — command injection possible if URL contains ; or |
        CosaSetSysCfgString("RedirectorURL", pString);
        return TRUE;
    }
}
```

**Consequence:** Command injection if URL contains `;`, `&`, `|`, or `'`.

**CORRECT:**
```c
if (strcmp(ParamName, "RedirectorURL") == 0) {
    if (isValidUrl(pString) != ANSC_STATUS_SUCCESS) {
        CcspTraceError(("%s: Invalid URL rejected\n", __FUNCTION__));
        return FALSE;
    }
    CosaSetSysCfgString("RedirectorURL", pString);
    return TRUE;
}
```

---

## 5. Trying to Disable Raptr RFC via TR-181

**WRONG:**
```c
// Expecting Raptr disable to work
BOOL AdvSecAgentRaptr_RFC_SetParamBoolValue(... BOOL bValue)
{
    if (bValue) CosaAdvSecAgentRaptrInit();
    else CosaAdvSecAgentRaptrDeInit();  // Never reached — returns FALSE before this
    return TRUE;
}
```

**Consequence:** Raptr RFC `SetParamBoolValue` returns `FALSE` for disable (bValue=FALSE). Code that assumes disable works will fail silently.

**CORRECT:**
```c
// Document that Raptr is enable-only
// The actual implementation returns FALSE for bValue=FALSE
// This is by design — Raptr cannot be disabled via TR-181
```

---

## 6. Accessing g_pAdvSecAgent Without NULL Check

**WRONG:**
```c
BOOL DeviceFingerPrint_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    *pBool = g_pAdvSecAgent->bEnable;  // Crash if CosaSecurityCreate failed
    return TRUE;
}
```

**Consequence:** NULL dereference crash if `CosaSecurityCreate` returned NULL in `COSA_Init`.

**CORRECT:**
```c
BOOL DeviceFingerPrint_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool)
{
    if (!g_pAdvSecAgent) {
        CcspTraceError(("%s: g_pAdvSecAgent is NULL\n", __FUNCTION__));
        return FALSE;
    }
    *pBool = g_pAdvSecAgent->bEnable;
    return TRUE;
}
```

---

## 7. Blocking I/O Under logMutex

**WRONG:**
```c
pthread_mutex_lock(&logMutex);
g_pAdvSecAgent->ulLoggingPeriod = newPeriod;
v_secure_system("start_adv_security.sh -setLogPeriod %lu", newPeriod);  // Blocks!
pthread_mutex_unlock(&logMutex);
```

**Consequence:** Logger thread blocked until script completes. Other threads waiting on logMutex are also blocked.

**CORRECT:**
```c
pthread_mutex_lock(&logMutex);
g_pAdvSecAgent->ulLoggingPeriod = newPeriod;
pthread_cond_signal(&logCond);
pthread_mutex_unlock(&logMutex);
// v_secure_system call outside lock scope
v_secure_system("start_adv_security.sh -setLogPeriod %lu", newPeriod);
```

---

## 8. Ignoring UserSpace RFC Dependency

**WRONG:**
```c
// Enable AdvSecSafeBrowsing RFC without checking UserSpace
BOOL AdvSecSafeBrowsing_RFC_SetParamBoolValue(... BOOL bValue)
{
    CosaAdvSecSafeBrowsingInit();  // May fail if UserSpace not enabled
    return TRUE;
}
```

**Consequence:** AdvSecSafeBrowsing_RFC and AdvSecCujoTelemetryWiFiFP_RFC both require UserSpace_RFC to be enabled first. Enabling without the dependency results in feature malfunction.

**CORRECT:**
```c
// The actual implementation checks UserSpace dependency internally
// When adding similar features, always verify prerequisite RFCs
if (!g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable) {
    CcspTraceWarning(("%s: UserSpace RFC not enabled, cannot enable SB-RFC\n", __FUNCTION__));
    return FALSE;
}
```
