/**
* Copyright 2024 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef CCSP_ADV_SECURITY_MOCK_H
#define CCSP_ADV_SECURITY_MOCK_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <experimental/filesystem>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_msgpack.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_base64.h>
#include <mocks/mock_rbus.h>
#include <mocks/mock_cm_hal.h>
#include <mocks/mock_platform_hal.h>
#include <mocks/mock_cJSON.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_webconfigframework.h>

extern SyscfgMock *g_syscfgMock;
extern SecureWrapperMock *g_securewrapperMock;
extern msgpackMock *g_msgpackMock;
extern UserTimeMock *g_usertimeMock;
extern SafecLibMock *g_safecLibMock;
extern AnscMemoryMock *g_anscMemoryMock;
extern BaseAPIMock *g_baseapiMock;
extern TraceMock *g_traceMock;
extern base64Mock *g_base64Mock;
extern rbusMock *g_rbusMock;
extern CmHalMock *g_cmHALMock;
extern PlatformHalMock *g_platformHALMock;
extern cjsonMock *g_cjsonMock;
extern SyseventMock *g_syseventMock;
extern webconfigFwMock *g_webconfigFwMock;
extern AnscWrapperApiMock *g_anscWrapperApiMock;

using namespace std;
using std::experimental::filesystem::exists;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArgPointee;
using ::testing::DoAll;

extern "C" {
#include "cosa_adv_security_dml.h"
#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_webconfig.h"
#include "advsecurity_helpers.h"
#include "advsecurity_param.h"
}

extern PCOSA_DATAMODEL_AGENT g_pAdvSecAgent;

static BOOL AdvsecSysEventHandlerStarted=FALSE;
static int sysevent_fd = 0;
static token_t sysEtoken;
static async_id_t async_id[4];

enum {SYS_EVENT_ERROR=-1, SYS_EVENT_OK, SYS_EVENT_TIMEOUT, SYS_EVENT_HANDLE_EXIT, SYS_EVENT_RECEIVED=0x10};

/*
 * Common base test fixture shared by all CcspAdvSecurity test suites.
 * Centralizes mock object lifecycle (SetUp/TearDown) and provides helper
 * methods for agent data-model allocation and sentinel-file management,
 * eliminating the duplication that previously existed across the three
 * fixture classes.
 */
class CcspAdvSecurityTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_msgpackMock = new msgpackMock();
        g_usertimeMock = new UserTimeMock();
        g_safecLibMock = new SafecLibMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_baseapiMock = new BaseAPIMock();
        g_traceMock = new TraceMock();
        g_base64Mock = new base64Mock();
        g_rbusMock = new rbusMock();
        g_cmHALMock = new CmHalMock();
        g_platformHALMock = new PlatformHalMock();
        g_cjsonMock = new cjsonMock();
        g_syseventMock = new SyseventMock();
        g_webconfigFwMock = new webconfigFwMock();
        g_anscWrapperApiMock = new AnscWrapperApiMock();
    }

    void TearDown() override {
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_msgpackMock;
        delete g_usertimeMock;
        delete g_safecLibMock;
        delete g_anscMemoryMock;
        delete g_baseapiMock;
        delete g_traceMock;
        delete g_base64Mock;
        delete g_rbusMock;
        delete g_cmHALMock;
        delete g_platformHALMock;
        delete g_cjsonMock;
        delete g_syseventMock;
        delete g_webconfigFwMock;
        delete g_anscWrapperApiMock;
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_msgpackMock = nullptr;
        g_usertimeMock = nullptr;
        g_safecLibMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_baseapiMock = nullptr;
        g_traceMock = nullptr;
        g_base64Mock = nullptr;
        g_rbusMock = nullptr;
        g_cmHALMock = nullptr;
        g_platformHALMock = nullptr;
        g_cjsonMock = nullptr;
        g_syseventMock = nullptr;
        g_webconfigFwMock = nullptr;
        g_anscWrapperApiMock = nullptr;
    }

    /* --- Agent data-model helpers --- */

    PCOSA_DATAMODEL_AGENT AllocateAgent() {
        PCOSA_DATAMODEL_AGENT pAgent = (PCOSA_DATAMODEL_AGENT)malloc(sizeof(COSA_DATAMODEL_AGENT));
        EXPECT_NE(pAgent, nullptr);
        if (pAgent) {
            memset(pAgent, 0, sizeof(COSA_DATAMODEL_AGENT));
        }
        return pAgent;
    }

    void AllocateAgentWithAdvSec() {
        g_pAdvSecAgent = AllocateAgent();
        ASSERT_NE(g_pAdvSecAgent, nullptr);
        g_pAdvSecAgent->pAdvSec = (COSA_DATAMODEL_ADVSEC *)malloc(sizeof(COSA_DATAMODEL_ADVSEC));
        ASSERT_NE(g_pAdvSecAgent->pAdvSec, nullptr);
        memset(g_pAdvSecAgent->pAdvSec, 0, sizeof(COSA_DATAMODEL_ADVSEC));
    }

    void AllocateAgentWithSafeBrowsing() {
        AllocateAgentWithAdvSec();
        g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
        ASSERT_NE(g_pAdvSecAgent->pAdvSec->pSafeBrows, nullptr);
        memset(g_pAdvSecAgent->pAdvSec->pSafeBrows, 0, sizeof(COSA_DATAMODEL_SB));
    }

    void AllocateAgentWithSoftflowd() {
        AllocateAgentWithAdvSec();
        g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
        ASSERT_NE(g_pAdvSecAgent->pAdvSec->pSoftFlowd, nullptr);
        memset(g_pAdvSecAgent->pAdvSec->pSoftFlowd, 0, sizeof(COSA_DATAMODEL_SOFTFLOWD));
    }

    void AllocateAgentWithAllFeatures() {
        AllocateAgentWithAdvSec();
        g_pAdvSecAgent->pAdvSec->pSafeBrows = (COSA_DATAMODEL_SB *)malloc(sizeof(COSA_DATAMODEL_SB));
        ASSERT_NE(g_pAdvSecAgent->pAdvSec->pSafeBrows, nullptr);
        memset(g_pAdvSecAgent->pAdvSec->pSafeBrows, 0, sizeof(COSA_DATAMODEL_SB));
        g_pAdvSecAgent->pAdvSec->pSoftFlowd = (COSA_DATAMODEL_SOFTFLOWD *)malloc(sizeof(COSA_DATAMODEL_SOFTFLOWD));
        ASSERT_NE(g_pAdvSecAgent->pAdvSec->pSoftFlowd, nullptr);
        memset(g_pAdvSecAgent->pAdvSec->pSoftFlowd, 0, sizeof(COSA_DATAMODEL_SOFTFLOWD));
        g_pAdvSecAgent->pAdvPC = (COSA_DATAMODEL_ADVPARENTALCONTROL *)malloc(sizeof(COSA_DATAMODEL_ADVPARENTALCONTROL));
        ASSERT_NE(g_pAdvSecAgent->pAdvPC, nullptr);
        memset(g_pAdvSecAgent->pAdvPC, 0, sizeof(COSA_DATAMODEL_ADVPARENTALCONTROL));
        g_pAdvSecAgent->pPrivProt = (COSA_DATAMODEL_PRIVACYPROTECTION *)malloc(sizeof(COSA_DATAMODEL_PRIVACYPROTECTION));
        ASSERT_NE(g_pAdvSecAgent->pPrivProt, nullptr);
        memset(g_pAdvSecAgent->pPrivProt, 0, sizeof(COSA_DATAMODEL_PRIVACYPROTECTION));
    }

    void FreeAgent() {
        if (!g_pAdvSecAgent) return;
        if (g_pAdvSecAgent->pAdvSec) {
            free(g_pAdvSecAgent->pAdvSec->pSafeBrows);
            free(g_pAdvSecAgent->pAdvSec->pSoftFlowd);
            free(g_pAdvSecAgent->pAdvSec);
        }
        free(g_pAdvSecAgent->pAdvPC);
        free(g_pAdvSecAgent->pPrivProt);
        free(g_pAdvSecAgent->pRabid);
        free(g_pAdvSecAgent->pAdvPC_RFC);
        free(g_pAdvSecAgent->pPrivProt_RFC);
        free(g_pAdvSecAgent->pDFIcmpv6_RFC);
        free(g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC);
        free(g_pAdvSecAgent->pAdvSecOTM_RFC);
        free(g_pAdvSecAgent->pAdvSecUserSpace_RFC);
        free(g_pAdvSecAgent->pRaptr_RFC);
        free(g_pAdvSecAgent->pAdvSecAgent_RFC);
        free(g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC);
        free(g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC);
        free(g_pAdvSecAgent->pAdvSecCujoTracer_RFC);
        free(g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC);
        free(g_pAdvSecAgent);
        g_pAdvSecAgent = nullptr;
    }

    /* --- Sentinel file helpers --- */

    void EnsureSentinelFile(const char *path) {
        sentinelCreated_ = false;
        FILE *file = fopen(path, "r");
        if (file) {
            fclose(file);
        } else {
            file = fopen(path, "w");
            if (file) fclose(file);
            sentinelCreated_ = true;
        }
        sentinelPath_ = path;
    }

    void CleanupSentinelFile() {
        if (sentinelCreated_ && !sentinelPath_.empty()) {
            remove(sentinelPath_.c_str());
        }
        sentinelCreated_ = false;
        sentinelPath_.clear();
    }

    /* --- Common mock expectation helpers --- */

    void ExpectSyscfgSetAndCommit(const char *key) {
        EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
            .WillOnce(Return(0));
        EXPECT_CALL(*g_syscfgMock, syscfg_set_nns(StrEq(key), _))
            .WillOnce(Return(0));
        EXPECT_CALL(*g_syscfgMock, syscfg_commit())
            .WillOnce(Return(0));
    }

    void ExpectSecureSystemCall(const char *substring) {
        EXPECT_CALL(*g_securewrapperMock, v_secure_system(HasSubstr(substring), _))
            .WillOnce(Return(0));
    }

private:
    bool sentinelCreated_ = false;
    std::string sentinelPath_;
};

#endif // CCSP_ADV_SECURITY_MOCK_H
