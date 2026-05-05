---
applyTo: "source/test/**/*.cpp,source/test/**/*.h"
---

# C++ Testing Standards (Google Test) for CcspAdvSecurity

## Test Framework

Use Google Test (gtest) and Google Mock (gmock) for all C++ test code.

## Test Organization

### File Structure
- One test file per source module: `cosa_adv_security_dml.c` → `CcspAdvSecurityDmlTest.cpp`
- Test fixtures for complex setups with full mock initialization
- Mocks in separate reusable files (e.g., `CcspAdvSecurityMock.h`)

```cpp
// GOOD: Test file structure
// filepath: source/test/CcspAdvSecurityDmlTest/CcspAdvSecurityDmlTest.cpp

extern "C" {
#include "cosa_adv_security_dml.h"
#include "cosa_adv_security_internal.h"
}

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "CcspAdvSecurityMock.h"

class CcspAdvSecurityDmlTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_safecLibMock = new SafecLibMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_traceMock = new TraceMock();
        g_rbusMock = new rbusMock();
        g_cmHALMock = new CmHalMock();
        g_platformHALMock = new PlatformHalMock();
        g_cjsonMock = new cjsonMock();
        g_syseventMock = new SyseventMock();
    }

    void TearDown() override {
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_safecLibMock;
        delete g_anscMemoryMock;
        delete g_traceMock;
        delete g_rbusMock;
        delete g_cmHALMock;
        delete g_platformHALMock;
        delete g_cjsonMock;
        delete g_syseventMock;
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_safecLibMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_traceMock = nullptr;
        g_rbusMock = nullptr;
        g_cmHALMock = nullptr;
        g_platformHALMock = nullptr;
        g_cjsonMock = nullptr;
        g_syseventMock = nullptr;
    }
};
```

## Testing Patterns

### Test C Code from C++
- Wrap C headers in `extern "C"` blocks
- Use RAII in tests for automatic cleanup
- Mock C functions using gmock global mock objects

```cpp
extern "C" {
#include "cosa_adv_security_internal.h"
}

#include <gtest/gtest.h>
#include "CcspAdvSecurityMock.h"

TEST_F(CcspAdvSecurityDmlTestFixture, DeviceFingerPrint_SetParamBoolValue_Enable) {
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
        .WillOnce(Return(0));

    BOOL result = DeviceFingerPrint_SetParamBoolValue(NULL, "Enable", TRUE);
    EXPECT_EQ(TRUE, result);
}
```

### Memory Leak Testing
- All tests must pass valgrind
- Use RAII wrappers for C resources
- Verify cleanup in TearDown

```cpp
// GOOD: RAII wrapper for COSA_DATAMODEL_AGENT
class AgentHandle {
    PCOSA_DATAMODEL_AGENT agent_;
public:
    AgentHandle() : agent_((PCOSA_DATAMODEL_AGENT)CosaSecurityCreate()) {}
    ~AgentHandle() {
        if (agent_) CosaSecurityRemove(agent_);
    }
    PCOSA_DATAMODEL_AGENT get() const { return agent_; }
    bool valid() const { return agent_ != nullptr; }
};

TEST(AgentTest, CreateAndDestroy) {
    AgentHandle agent;
    EXPECT_TRUE(agent.valid());
}
```

### Mocking syscfg/sysevent

```cpp
// GOOD: Mock for syscfg operations
class MockSyscfg {
public:
    MOCK_METHOD(int, syscfg_get, (const char*, const char*, char*, int));
    MOCK_METHOD(int, syscfg_set_nns, (const char*, const char*));
    MOCK_METHOD(int, syscfg_commit, ());
};

TEST_F(CcspAdvSecurityInternalTestFixture, CosaAdvSecStartFeatures_SafeBrowsing) {
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns(_, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_commit())
        .WillOnce(Return(0));
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
        .WillOnce(Return(0));

    CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING);
    // Verify syscfg was set and script was called
}
```

## Required Test Categories

Every change must include tests for:

- **Feature enable/disable**: success and failure (syscfg error, script error)
- **RFC toggle**: Init/DeInit with valid and invalid states
- **DML handlers**: GetParamBoolValue, SetParamBoolValue for all parameters
- **Input validation**: isValidUrl with valid HTTPS, non-HTTPS, injection characters
- **WebConfig**: blob processing success and malformed input
- **Edge cases**: NULL g_pAdvSecAgent, bridge mode, concurrent Init/DeInit

## Test Quality Standards

- ≥80% branch coverage for new code
- All error paths exercised
- Mock expectations verified (strict mocks preferred)
- No test interdependencies
- Each test file compiles independently
