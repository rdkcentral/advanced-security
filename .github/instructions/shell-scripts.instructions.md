---
applyTo: "**/*.sh"
---

# Shell Script Standards for CcspAdvSecurity

## Platform Independence

### Use POSIX Shell Where Possible
- Scripts in `scripts/` use `#!/bin/bash` due to source dependencies
- Avoid bashisms when POSIX alternatives exist
- Test on busybox ash (common in embedded devices)

```bash
#!/bin/sh
# GOOD: POSIX compliant

# BAD: Bash-specific
if [[ $var == "value" ]]; then  # Use [ ] instead
    array=(1 2 3)  # Arrays not in POSIX
fi

# GOOD: POSIX compliant
if [ "$var" = "value" ]; then
    set -- 1 2 3  # Use positional parameters
fi
```

## Resource Awareness

### Minimize Process Spawning
- Use shell builtins when possible
- Avoid pipes when not necessary
- Batch operations to reduce forks

```bash
# BAD: Multiple processes
cat /tmp/advsec_log | grep "SafeBrowsing" | wc -l

# GOOD: Fewer processes
grep -c "SafeBrowsing" /tmp/advsec_log
```

### Memory Usage
- Avoid reading entire files into variables
- Process streams line by line
- Clean up temporary files and sentinel files

```bash
# BAD: Loads entire file into memory
content=$(cat /tmp/advsec_agent.log)
echo "$content" | grep ERROR

# GOOD: Stream processing
grep ERROR /tmp/advsec_agent.log
```

## Error Handling

### Always Check Exit Codes
```bash
# GOOD: Check critical operations
if ! mkdir -p /tmp/advsec_config_params; then
    echo_t "Advanced Security : Failed to create config dir" >> ${ADVSEC_AGENT_LOG_PATH}
    exit 1
fi

# GOOD: Trap for cleanup
cleanup() {
    rm -f "$ADVSEC_INITIALIZING"
}
trap cleanup EXIT INT TERM
```

## Script Quality

### Defensive Programming
```bash
# GOOD: Quote all variables
rm -f "$SAFEBRO_ENABLE"  # Not: rm -f $SAFEBRO_ENABLE

# GOOD: Use -- to separate options from arguments
grep -r -- "$pattern" "$directory"

# GOOD: Validate inputs
if [ -z "$1" ]; then
    echo "Usage: $0 <flag>" >&2
    exit 1
fi
```

### Logging
```bash
# Use echo_t for timestamped logging (sourced from log_timestamp.sh)
echo_t "Advanced Security : Starting agent services" >> ${ADVSEC_AGENT_LOG_PATH}

# Log state transitions
echo_t "Advanced Security : Feature $feature_name $action" >> ${ADVSEC_AGENT_LOG_PATH}
```

## CcspAdvSecurity-Specific Guidelines

### cujo-agent Lifecycle Scripts
- `advsec.sh` sets up environment (agent binary paths, sentinel files, module paths)
- `start_adv_security.sh` is the main entry point called by `v_secure_system()`
- Scripts that change feature state must update sentinel files (`/tmp/advsec_*`)
- Always check if cujo-agent is installed before attempting operations
- Check bridge mode before enabling agent

```bash
# GOOD: Check agent installation
if [ "x$(advsec_is_agent_installed)" != "xYES" ]; then
    echo_t "Advanced Security : Agent not installed" >> ${ADVSEC_AGENT_LOG_PATH}
    exit 0
fi

# GOOD: Check bridge mode
bridge_mode=$(syscfg get bridge_mode)
if [ "$bridge_mode" = "2" ]; then
    echo_t "Advanced Security : Bridge mode, skipping" >> ${ADVSEC_AGENT_LOG_PATH}
    exit 0
fi
```

### Sentinel Files
| File | Purpose |
|------|---------|
| `/tmp/advsec_initialized` | Agent fully initialized |
| `/tmp/advsec_initializing` | Initialization in progress (prevent re-entry) |
| `/tmp/advsec_daemons_hibernating` | Agent in hibernation state |
| `/tmp/advsec_softflowd_enable` | Softflowd feature active |
| `/tmp/advsec_safebro_enable` | SafeBrowsing feature active |
| `/tmp/advsec_wifidcl_init` | WiFi data collection initialized |

### Log Parsing
- Parse logs with stable patterns for feature enable/disable events
- Use `echo_t` patterns for timestamped entries
- Avoid assumptions about log format changes across firmware versions

## Testing Scripts

### Use shellcheck
```bash
# Run shellcheck on all scripts
find . -name "*.sh" -exec shellcheck {} +
```
