/*
 *
 * Copyright 2016 Comcast Cable Communications Management, LLC
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
 * SPDX-License-Identifier: Apache-2.0
*/

#ifndef  _COSA_NETWORK_INTELLIGENCE_WEBCONFIG_H
#define  _COSA_NETWORK_INTELLIGENCE_WEBCONFIG_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "ansc_status.h"
#include "ansc_platform.h"

#include "webconfig_framework.h"
#include "networkintelligence_param.h"

pErr ni_webconfig_process_request(void *Data);
int ni_webconfig_rollback();
void ni_webconfig_free_resources(void *arg);
int ni_webconfig_handle_blob(networkintelligenceparam_t *feature);

#endif
