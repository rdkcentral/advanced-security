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

#ifndef __NETWORKINTELLIGENCE_PARAM_H__
#define __NETWORKINTELLIGENCE_PARAM_H__
#include <stdint.h>
#include <stdlib.h>
#include <msgpack.h>

#define NI_WEBCONFIG_SUBDOC_NAME "networkintelligence"

typedef struct
{
    bool  network_intelligence_activate;

} networkintelligenceparam_t;

typedef struct {
    networkintelligenceparam_t  *param;
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
} networkintelligencedoc_t;
/**
 *  This function converts a msgpack buffer into a networkintelligencedoc_t
 *  structure if possible.
 *
 *  @param buf the buffer to convert
 *  @param len the length of the buffer in bytes
 *
 *  @return NULL on error, success otherwise
 */
networkintelligencedoc_t* networkintelligencedoc_convert( const void *buf, size_t len );
/**
 *  This function destroys a networkintelligencedoc_t object.
 *
 *  @param d the networkintelligencedoc to destroy
 */
void networkintelligencedoc_destroy( networkintelligencedoc_t *d );
/**
 *  This function returns a general reason why the conversion failed.
 *
 *  @param errnum the errno value to inspect
 *
 *  @return the constant string (do not alter or free) describing the error
 */
const char* networkintelligencedoc_strerror( int errnum );
#endif
