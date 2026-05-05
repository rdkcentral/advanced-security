---
applyTo: "**/Makefile.am,**/configure.ac,**/*.ac,**/*.mk"
---

# Build System Standards (Autotools) for CcspAdvSecurity

## Autotools Best Practices

### configure.ac
- Check for required headers and functions
- Provide clear error messages for missing CCSP SDK dependencies
- Support cross-compilation for ARM/MIPS targets
- Allow feature toggles for optional backends

```autoconf
# GOOD: Check for required features
AC_CHECK_HEADERS([pthread.h], [],
    [AC_MSG_ERROR([pthread.h is required])])

AC_CHECK_LIB([pthread], [pthread_create], [],
    [AC_MSG_ERROR([pthread library is required])])

# GOOD: Unit test support toggle
AC_ARG_ENABLE([unitTestDockerSupport],
    AS_HELP_STRING([--enable-unitTestDockerSupport], [Enable Docker support for unit testing]),
    [UNIT_TEST_DOCKER_SUPPORT=true],
    [UNIT_TEST_DOCKER_SUPPORT=false])

AM_CONDITIONAL([UNIT_TEST_DOCKER_SUPPORT], [test x$UNIT_TEST_DOCKER_SUPPORT = xtrue])

# GOOD: Optional WiFi data collection
AC_ARG_ENABLE([wifidatacollection],
    AS_HELP_STRING([--enable-wifidatacollection], [Enable WiFi data collection support]),
    [enable_wifidcl=$enableval],
    [enable_wifidcl=no])

AM_CONDITIONAL([WITH_WIFI_DATA_COLLECTION], [test "x$enable_wifidcl" = "xyes"])
```

### Makefile.am
- Use non-recursive makefiles when possible
- Minimize intermediate libraries
- Support parallel builds
- Link only what's needed

```makefile
# GOOD: Minimal linking
lib_LTLIBRARIES = libadvsec_dml.la

libadvsec_dml_la_SOURCES = \
    cosa_adv_security_dml.c \
    cosa_adv_security_internal.c \
    cosa_adv_security_webconfig.c \
    plugin_main.c \
    advsecurity_helpers.c \
    advsecurity_param.c

libadvsec_dml_la_CFLAGS = \
    -DFEATURE_SUPPORT_RDKLOG

libadvsec_dml_la_LDFLAGS = \
    -lpthread \
    -lsyscfg \
    -lsysevent \
    -lcjson

# GOOD: Conditional compilation
if WITH_WIFI_DATA_COLLECTION
libadvsec_dml_la_SOURCES += cujoagent_dcl_api.c
libadvsec_dml_la_CFLAGS += -DWIFI_DATA_COLLECTION
endif

if UNIT_TEST_DOCKER_SUPPORT
SUBDIRS += test
endif
```

## Cross-Compilation Support

### Platform Detection
```autoconf
# Support different target platforms
case "$host" in
    *-linux*)
        AC_DEFINE([PLATFORM_LINUX], [1], [Linux platform])
        ;;
    arm*|*-arm*)
        AC_DEFINE([PLATFORM_ARM], [1], [ARM platform])
        ;;
    mips*|*-mips*)
        AC_DEFINE([PLATFORM_MIPS], [1], [MIPS platform])
        ;;
esac
```

### Compiler Flags
```makefile
# Platform-specific flags
if COSA_BCM_MIPS
AM_CFLAGS += -D_COSA_BCM_MIPS_
endif

if COSA_INTEL_XB3_ARM
AM_CFLAGS += -D_COSA_INTEL_XB3_ARM_
endif

# Debug vs Release
if DEBUG_BUILD
AM_CFLAGS += -g -O0 -DDEBUG
else
AM_CFLAGS += -O2 -DNDEBUG
endif
```

## Dependency Management

### Package Config
```autoconf
# Use pkg-config for external dependencies
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.6], [], [AC_MSG_WARN([dbus-1 not found])])
PKG_CHECK_MODULES([RBUS], [rbus], [], [AC_MSG_WARN([rbus not found])])
AC_SUBST([DBUS_CFLAGS])
AC_SUBST([DBUS_LIBS])
```

### Header Organization
```makefile
# Include paths
AM_CPPFLAGS = -I$(top_srcdir)/source/AdvSecurityDml \
              -I$(top_srcdir)/source/AdvSecuritySsp \
              $(DBUS_CFLAGS) \
              $(RBUS_CFLAGS)
```

## Testing Integration

```makefile
# Test targets
check-local:
	@echo "Running memory leak tests..."
	@for test in $(TESTS); do \
		valgrind --leak-check=full \
		         --error-exitcode=1 \
		         ./$$test || exit 1; \
	done

# Code coverage
if ENABLE_COVERAGE
AM_CFLAGS += --coverage
AM_LDFLAGS += --coverage
endif

coverage: check
	$(LCOV) --capture --directory . --output-file coverage.info
	$(GENHTML) coverage.info --output-directory coverage
```

## Build Validation

- Verify `autoreconf -i`, `./configure`, and `make` on a clean workspace
- Confirm test targets remain callable from CI workflows
- Verify cross-compilation with `--host=arm-linux-gnueabihf`
- Test with and without `--enable-unitTestDockerSupport`
