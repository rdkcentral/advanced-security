# Advanced Security Component Documentation

## Quick Links

| Document | Content |
|----------|---------|
| [Architecture](architecture.md) | System design, components, plugin model, initialization, threading, build flags |
| [Workflows](workflows.md) | Startup, feature enable/disable, WebConfig processing, RFC toggles, recovery |
| [Troubleshooting](troubleshooting.md) | Decision trees, log signatures, diagnostic commands, RCA workflow |
| [Developer Playbook](developer-playbook.md) | Shell commands for debugging, TR-181 validation, feature testing |
| [Onboarding](onboarding.md) | First 30 minutes new engineer guide |
| [Data Flow](DATA_FLOW.md) | Input → processing → output paths, log generation, alert lifecycle |
| [Security Model](SECURITY_MODEL.md) | Policies, threat detection logic, enforcement mechanisms, trust boundaries |
| [Tools Reference](TOOLS.md) | Complete function/script/API catalog with inputs, outputs, source files |
| [API Reference](reference/api-reference.md) | Internal API signatures, lifecycle, DML catalog |
| [TR-181 Matrix](reference/tr181-matrix.md) | Parameter-to-code ownership map |
| [Feature Catalog](reference/feature-catalog.md) | Feature modules, RFC toggles, WebConfig integration |

## Structure

```
docs/
├── README.md                  ← Navigation hub
├── architecture.md            ← System design (HLD + LLD merged)
├── workflows.md               ← Runtime operational flows
├── DATA_FLOW.md               ← Input/output paths, log generation, alerts
├── SECURITY_MODEL.md          ← Policies, threats, enforcement, trust boundaries
├── TOOLS.md                   ← Complete function/script/API catalog
├── troubleshooting.md         ← Diagnosis, decision trees, RCA
├── developer-playbook.md      ← Commands & validation
├── onboarding.md              ← First 30 minutes guide
└── reference/
    ├── api-reference.md       ← Internal API reference
    ├── tr181-matrix.md        ← TR-181 ownership
    └── feature-catalog.md     ← Feature & RFC catalog
```

## Component Overview

Advanced Security (`CcspAdvSecuritySsp`) provides a TR-181 parameter management interface for network security features on RDK-B devices. It uses a COSA plugin architecture where each security feature — DeviceFingerPrint, SafeBrowsing, Softflowd, AdvancedParentalControl, PrivacyProtection — has dedicated DML handlers. The component coordinates with the external advanced security agent (`cujo-agent`) for actual threat detection and enforcement.

Key source files: `plugin_main.c` (DML registration), `cosa_adv_security_internal.c` (lifecycle and feature init), `cosa_adv_security_dml.c` (TR-181 handlers), `advsecurity_param.c` (msgpack processing), `ssp_main.c` (daemon bootstrap).

**New engineers:** Read in order — Architecture → Workflows → Developer Playbook → Troubleshooting.

## Build & Test

```bash
./autogen.sh && ./configure && make
make -C source/test                    # unit tests
source/test/run_ut.sh                  # test runner with coverage
```
