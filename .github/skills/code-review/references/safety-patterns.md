# Safety Patterns — CcspAdvSecurity

Memory and thread safety patterns for code review reference.

---

## Memory Safety Patterns

### 1. Allocation Check
```c
// CORRECT
PCOSA_DATAMODEL_AGENT pAgent = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
if (pAgent == NULL) {
    CcspTraceError(("%s: AnscAllocateMemory failed\n", __FUNCTION__));
    return NULL;
}
memset(pAgent, 0, sizeof(COSA_DATAMODEL_AGENT));

// WRONG — NULL dereference if allocation fails
PCOSA_DATAMODEL_AGENT pAgent = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
pAgent->bEnable = TRUE;
```

### 2. Single-Exit Cleanup (goto cleanup)
```c
// CORRECT (pattern from CosaSecurityCreate)
ANSC_HANDLE CosaSecurityCreate(void) {
    PCOSA_DATAMODEL_AGENT pAgent = NULL;
    PCOSA_DATAMODEL_ADVSEC pAdvSec = NULL;
    PCOSA_DATAMODEL_SB pSB = NULL;

    pAgent = AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
    if (!pAgent) goto cleanup;

    pAdvSec = AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));
    if (!pAdvSec) goto cleanup;

    pSB = AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
    if (!pSB) goto cleanup;

    pAgent->pAdvSec = pAdvSec;
    pAdvSec->pSafeBrows = pSB;
    return (ANSC_HANDLE)pAgent;

cleanup:
    AnscFreeMemory(pSB);
    AnscFreeMemory(pAdvSec);
    AnscFreeMemory(pAgent);
    return NULL;
}

// WRONG — leak on error
pAdvSec = AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));
pSB = AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
if (!pSB) return NULL;  // pAdvSec leaked!
```

### 3. Safe String Copy
```c
snprintf(pAgent->redirectorURL, sizeof(pAgent->redirectorURL), "%s", input);  // CORRECT
strcpy(pAgent->redirectorURL, input);  // WRONG — no bounds
```

### 4. Use-After-Free Prevention
```c
AnscFreeMemory(pAgent->pAdvSec);
pAgent->pAdvSec = NULL;  // CORRECT

// In DML callback: check before access
if (g_pAdvSecAgent == NULL) return FALSE;
```

### 5. Safe realloc
```c
char *tmp = realloc(buf, newSize);       // CORRECT
if (!tmp) return RETURN_ERROR;
buf = tmp;

buf = realloc(buf, newSize);             // WRONG — original leaked if fails
```

### 6. Global Singleton Check
```c
// CORRECT — always check g_pAdvSecAgent
if (g_pAdvSecAgent && g_pAdvSecAgent->pAdvSec && g_pAdvSecAgent->pAdvSec->pSafeBrows) {
    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = bValue;
}

// WRONG — assumes chain is valid
g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = bValue;
```

### 7. Ownership Documentation
```c
/** @return Heap-allocated COSA_DATAMODEL_AGENT. Caller owns via CosaSecurityRemove(). */
ANSC_HANDLE CosaSecurityCreate(void);
```

---

## Thread Safety Patterns

### 1. Mutex-Protected Log State
```c
// CORRECT
pthread_mutex_lock(&logMutex);
g_pAdvSecAgent->ulLoggingPeriod = newPeriod;
pthread_cond_signal(&logCond);  // Wake logger thread
pthread_mutex_unlock(&logMutex);

// WRONG — unsynchronized update
g_pAdvSecAgent->ulLoggingPeriod = newPeriod;
```

### 2. Condition Variable with While Loop
```c
// CORRECT — handles spurious wakeup (from advsec_logger_th)
pthread_mutex_lock(&logMutex);
while (!shouldLog) {
    n = pthread_cond_timedwait(&logCond, &logMutex, &_ts);
    if (n == ETIMEDOUT) break;
}
pthread_mutex_unlock(&logMutex);

// WRONG: if (!shouldLog) pthread_cond_wait(...)
```

### 3. Thread Creation
```c
err = pthread_create(&logger_thread, NULL, advsec_logger_th, NULL);  // CORRECT
if (err != 0) {
    CcspTraceError(("%s: pthread_create failed for logger\n", __FUNCTION__));
    return;
}

pthread_create(&tid, NULL, func, arg);  // WRONG — return ignored
```

### 4. No Blocking I/O Under Lock
```c
// CORRECT — script call outside lock
pthread_mutex_unlock(&logMutex);
v_secure_system("start_adv_security.sh -enable");

// WRONG — blocks logger thread
pthread_mutex_lock(&logMutex);
v_secure_system("start_adv_security.sh -enable");
pthread_mutex_unlock(&logMutex);
```

---

## Security Patterns

### 1. URL Validation
```c
// CORRECT — validate before use
if (isValidUrl(pInputUrl) != ANSC_STATUS_SUCCESS) {
    CcspTraceError(("%s: Invalid URL\n", __FUNCTION__));
    return FALSE;
}

// WRONG — use unvalidated input
v_secure_system("curl %s", userUrl);
```

### 2. Safe Shell Invocation
```c
// CORRECT
v_secure_system("start_adv_security.sh -enable");

// WRONG — command injection possible
system(cmd_buffer);
```

---

## Red Flags

### Memory
- `AnscAllocateMemory` without NULL check within 3 lines
- `AnscFreeMemory()` without `ptr = NULL` in long-lived scope
- `strcpy` or `sprintf` anywhere
- Error `return` between allocation and its free
- Accessing `g_pAdvSecAgent->` chain without NULL checks

### Thread
- `logMutex` lock without matching unlock on all paths
- `v_secure_system()` called under `logMutex`
- Logger/sysevent thread not checking shutdown condition

### Security
- Raw `system()` call anywhere
- URL string passed to shell without `isValidUrl()` check
- Logging MAC addresses or subscriber data at INFO level
