---
name: safety-analyzer
description: "Analyze C/C++ code for memory safety, thread safety, and platform portability issues. Use when reviewing code, debugging crashes/races, or preparing for cross-platform deployment in CcspAdvSecurity."
---

# Safety Analyzer for CcspAdvSecurity

Systematically analyze code for memory safety, thread safety, and platform portability issues that cause crashes, security vulnerabilities, deadlocks, or cross-platform failures.

## When to Use

- Reviewing new code with dynamic memory or multi-threading
- Debugging memory-related crashes, race conditions, or deadlocks
- Preparing code for production or cross-platform deployment
- Investigating memory leaks, heap fragmentation, or lock contention

---

## Memory Safety Analysis

### Step 1: Identify All Allocations
Search for: `AnscAllocateMemory`, `malloc`, `calloc`, `realloc`, `strdup`, `strndup`, `fopen`, `open`, `pthread_create`, `pthread_mutex_init`.

For each: (1) Return value checked? (2) Matching free/close? (3) Error paths also free? (4) No double-free?

### Step 2: Check Pointer Lifetimes
For each pointer: When assigned? When freed? Used after free? NULL-initialized?

Critical pointers in CcspAdvSecurity:
- `g_pAdvSecAgent` — global singleton, created in `COSA_Init`, freed in `COSA_Unload`
- `g_pAdvSecAgent->pAdvSec->pSafeBrows` — nested allocation chain
- `g_cujoagent_dcl` — conditional on `WIFI_DATA_COLLECTION`

### Step 3: Review Buffer Operations
- `strcpy` → should be `snprintf`
- `sprintf` → should be `snprintf`
- `memcpy` → verify no overlap, validate size
- `strncpy` → verify null termination

### Common Memory Issues

```c
// Unchecked allocation
PCOSA_DATAMODEL_AGENT pAgent = AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
pAgent->bEnable = TRUE;  // Crash if NULL

// Leak on error (nested allocations)
pAdvSec = AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));
pSB = AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
if (!pSB) return NULL;  // Leaked pAdvSec!

// Use after free in DML callback
CosaSecurityRemove(g_pAdvSecAgent);
// Later DML callback accesses g_pAdvSecAgent->bEnable  // UAF!
```

---

## Thread Safety Analysis

### Step 1: Identify Shared Data
Globals: `g_pAdvSecAgent` (singleton), `logMutex`/`logCond` (logger sync), all `g_*Enabled` syscfg key strings (read-only after init — safe).

### Step 2: Analyze Lock Usage
For each mutex: initialized? destroyed? balanced lock/unlock? correct ordering? held during expensive I/O?

CcspAdvSecurity has:
- `logMutex` — protects log period and condition variable
- `logCond` — signals logger thread for period changes

### Step 3: Check Race Conditions
```c
// RACE: g_pAdvSecAgent accessed from DML thread without synchronization
// while COSA_Unload may be freeing it
if (g_pAdvSecAgent->bEnable) {
    CosaAdvSecInit();  // g_pAdvSecAgent could be freed between check and use
}
```

### Step 4: Deadlock Detection
- Logger thread holds `logMutex` during `pthread_cond_timedwait`
- DML thread acquires `logMutex` to signal period change
- No risk if `v_secure_system()` is never called under `logMutex`

### Common Thread Issues

```c
// Missing unlock on error
pthread_mutex_lock(&logMutex);
if (error_condition) {
    return;  // Lock not released!
}
pthread_mutex_unlock(&logMutex);

// Blocking I/O under lock
pthread_mutex_lock(&logMutex);
v_secure_system("start_adv_security.sh -enable");  // Blocks!
pthread_mutex_unlock(&logMutex);
```

---

## Platform Portability Analysis

### Key Checks
1. **Integer types**: Use `stdint.h` types (`uint32_t`, `int16_t`), not `int`/`long`
2. **Pointer casts**: Use `uintptr_t`, not `long`
3. **Platform guards**: `#ifdef _COSA_BCM_MIPS_`, `_COSA_INTEL_XB3_ARM_`, `CONFIG_CISCO`
4. **Vendor abstraction**: `CONFIG_VENDOR_NAME` macro varies by platform
5. **CM MAC retrieval**: Different HAL calls per platform (cm_hal vs dpoe_hal)

---

## Verification Commands

```bash
# Static analysis
cppcheck --enable=all --inconclusive source/AdvSecurityDml/

# Memory analysis
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./source/test/CcspAdvSecurityDmlTest/CcspAdvSecurity_gtest.bin

# Thread analysis
valgrind --tool=helgrind --track-lockorders=yes ./source/test/CcspAdvSecurityDmlTest/CcspAdvSecurity_gtest.bin

# Cross-compilation
./configure --host=arm-linux-gnueabihf && make clean && make
```

## Output Format

```
## Safety Analysis

### Critical Issues (must fix)
1. [file.c:123] Description

### Warnings (should fix)
1. [file.c:234] Description

### Recommendations
1. Description

### Suggested Fixes
[Specific code changes]
```
