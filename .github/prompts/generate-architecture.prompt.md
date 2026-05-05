---
description: "Generate architecture documentation for Advanced Security component modeled after the Cellular Manager architecture doc"
agent: "agent"
---

# Generate Architecture Documentation

Generate a comprehensive `docs/architecture.md` for the **Advanced Security (CcspAdvSecurity)** component.

## Reference

Use the Cellular Manager architecture doc as the structural template:
[architecture.md](../../../cellular/cellular-manager/docs/architecture.md)

## Source Files to Analyze

Read these source files to extract accurate architectural details:

- [ssp_main.c](../../source/AdvSecuritySsp/ssp_main.c) — daemon bootstrap, signal handling, privilege drop
- [ssp_action.c](../../source/AdvSecuritySsp/ssp_action.c) — component registration, CPE controller, data model XML
- [plugin_main.c](../../source/AdvSecurityDml/plugin_main.c) — COSA plugin entry, DML function registration
- [cosa_adv_security_internal.h](../../source/AdvSecurityDml/cosa_adv_security_internal.h) — core data model structs, feature enums, lifecycle APIs
- [cosa_adv_security_dml.h](../../source/AdvSecurityDml/cosa_adv_security_dml.h) — TR-181 DML API declarations
- [cosa_adv_security_webconfig.h](../../source/AdvSecurityDml/cosa_adv_security_webconfig.h) — WebConfig integration
- [advsecurity_helpers.h](../../source/AdvSecurityDml/advsecurity_helpers.h) — msgpack decoding helpers
- [cujoagent_dcl_api.h](../../source/AdvSecurityDml/cujoagent_dcl_api.h) — WiFi data collection layer
- [advsecurity_param.c](../../source/AdvSecurityDml/advsecurity_param.c) — parameter handling
- [TR181-AdvSecurity.xml](../../config/TR181-AdvSecurity.xml) — data model XML
- [configure.ac](../../configure.ac) — build flags and conditionals

## Required Sections

1. **System Overview** — ASCII or Mermaid diagram showing CcspAdvSecurity within the RDK-B stack (interactions with CR, PSM, WebConfig, Security Agent, Protocol Agents)
2. **Components** — Table mapping component name → source files → purpose (SSP, DML Plugin, WebConfig, DCL, Helpers)
3. **Initialization Sequence** — Numbered steps from `main()` through `CosaSecurityInitialize()`, covering privilege drop, daemonize, message bus, CPE controller, plugin load, feature init
4. **Feature Modules** — Table of each security feature (DeviceFingerPrint, SafeBrowsing, Softflowd, AdvancedParentalControl, PrivacyProtection, RabidFramework) with their TR-181 object, RFC toggle, init/deinit functions
5. **RFC Feature Flags** — Complete table of all RFC toggles with their DML parameter name and controlled behavior
6. **Threading Model** — Document main thread, event loop, any worker threads
7. **IPC and Dependencies** — External dependencies (CCSP bus, PSM, WebConfig framework, Security Agent socket, kernel netfilter)
8. **Build Flags** — Table of `configure.ac` options (`--enable-downloadmodule`, `--enable-wifidcl`, `--with-ccsp-arch`) and their compile-time effects
9. **Data Model Registration** — How `TR181-AdvSecurity.xml` is registered with the Component Registrar

## Style Guidelines

- Use Mermaid diagrams for system overview and initialization flow
- Include file path references as relative links
- Keep tables concise with columns: Component | Files | Purpose
- Match the depth and tone of the Cellular Manager architecture doc
- Derive all content from actual source code — do not invent features
