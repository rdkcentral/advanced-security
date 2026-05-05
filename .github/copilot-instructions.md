# Project Guidelines

## Code Style
- Language focus: C for runtime code, C++ for tests, shell for agent lifecycle scripts.
- Follow existing module prefixes and naming patterns in source:
  - `cosa_adv_security_*` for internal/DML layers
  - `CosaAdvSec*` / `Cosa*Init` / `Cosa*DeInit` for RFC Init/DeInit functions
  - `DeviceFingerPrint_*`, `SafeBrowsing_*`, `Softflowd_*`, `AdvancedParentalControl_*`, `PrivacyProtection_*` for DML handlers
- Prefer `CcspTraceInfo/Error/Warning` logging patterns over ad-hoc output.
- Keep syscfg key strings consistent with existing globals in `source/AdvSecurityDml/cosa_adv_security_internal.c`.

See:
- `docs/architecture.md`
- `docs/reference/api-reference.md`

## Architecture
- This component is a CCSP plugin (DML shared library) loaded by `CcspAdvSecuritySsp` daemon.
- Core boundaries:
  - DML handlers: `source/AdvSecurityDml/cosa_adv_security_dml.c`
  - Internal lifecycle: `source/AdvSecurityDml/cosa_adv_security_internal.c`
  - Data model structs: `source/AdvSecurityDml/cosa_adv_security_internal.h`
  - Plugin registration: `source/AdvSecurityDml/plugin_main.c`
  - SSP daemon: `source/AdvSecuritySsp/ssp_main.c`
  - WebConfig: `source/AdvSecurityDml/cosa_adv_security_webconfig.c`
  - Scripts: `scripts/start_adv_security.sh`, `scripts/advsec.sh`
- Feature lifecycle pattern: TR-181 Set → DML handler → Init/DeInit → syscfg persist → v_secure_system(script flag)
- RFC toggles follow identical pattern: DML SetParamBoolValue → CosaXxxInit/DeInit → CosaSetSysCfgUlong → v_secure_system
- SafeBrowsing/Softflowd Validate/Commit/Rollback are NO-OPs; actual logic is in SetParamBoolValue.

See:
- `docs/workflows.md`
- `docs/reference/tr181-matrix.md`
- `docs/reference/feature-catalog.md`

## Build and Test
- Preferred bootstrap/build:
  - `./autogen.sh`
  - `./configure`
  - `make`
- Unit tests:
  - `./configure --enable-unitTestDockerSupport`
  - `make -C source/test`
  - `source/test/run_ut.sh`
- CI references:
  - `.github/workflows/L1-tests.yml`
  - `.github/workflows/native-build.yml`

See:
- `docs/onboarding.md`
- `docs/developer-playbook.md`

## Conventions
- Link, do not duplicate: prefer referencing docs under `docs/` and `.github/` instead of embedding long procedures.
- Treat build flags as behavior-changing (`WIFI_DATA_COLLECTION`, `DOWNLOADMODULE_ENABLE`, `WAN_FAILOVER_SUPPORTED`, `_COSA_BCM_MIPS_`, `_COSA_INTEL_XB3_ARM_`).
- All feature enable/disable goes through `v_secure_system()` calling `start_adv_security.sh` — never call shell scripts directly from DML code via `system()`.
- Command injection prevention: validate all URL/string inputs using `isValidUrl()` before passing to shell.
- When triaging incidents, include timeline, evidence, hypothesis confidence, and disproof checks.

See:
- `docs/troubleshooting.md`
- `.github/skills/incident-analysis/SKILL.md`
