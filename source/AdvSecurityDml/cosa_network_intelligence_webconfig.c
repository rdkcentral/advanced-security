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

#include "cosa_network_intelligence_webconfig.h"
#include "webconfig_framework.h"
#include <errno.h>
#include <syscfg/syscfg.h>
#include "safec_lib_common.h"

/* CallBack API to execute Network Intelligence Blob request */
pErr ni_webconfig_process_request(void *Data)
{
    pErr execRetVal = NULL;
    errno_t rc = -1;
    int ind = -1;

    execRetVal = (pErr) AnscAllocateMemory (sizeof(Err));
    if (execRetVal == NULL )
    {
        CcspTraceError(("%s : AnscAllocateMemory failed\n",__FUNCTION__));
        return execRetVal;
    }

    rc = memset_s(execRetVal, sizeof(Err), 0, sizeof(Err));
    ERR_CHK(rc);

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;

    networkintelligencedoc_t *ni = (networkintelligencedoc_t *) Data ;
    if( ni != NULL && ni->subdoc_name != NULL && ni->param != NULL )
    {
        CcspTraceInfo(("%s: ni->subdoc_name is %s\n", __FUNCTION__, ni->subdoc_name));
        CcspTraceInfo(("%s: ni->version is %lu\n", __FUNCTION__, (long)ni->version));
        CcspTraceInfo(("%s: ni->transaction_id %lu\n",__FUNCTION__, (long) ni->transaction_id));
        CcspTraceInfo(("%s: network_intelligence_activate[%d]\n",
            __FUNCTION__, ni->param->network_intelligence_activate));

        rc = strcmp_s(NI_WEBCONFIG_SUBDOC_NAME, strlen(NI_WEBCONFIG_SUBDOC_NAME), ni->subdoc_name, &ind);
        ERR_CHK(rc);
        if((rc == EOK) && (ind == 0))
        {
            int ret = ni_webconfig_handle_blob(ni->param);

            CcspTraceInfo(("%s: Return value = %d\n",__FUNCTION__, ret));

            if ( ret == BLOB_EXEC_SUCCESS )
            {
                if ( ni->param->network_intelligence_activate == TRUE )
                {
                    strncpy(execRetVal->ErrorMsg,"activated",sizeof(execRetVal->ErrorMsg)-1);
                }
                else
                {
                    strncpy(execRetVal->ErrorMsg,"deactivated",sizeof(execRetVal->ErrorMsg)-1);
                }
            }
            else
            {
                execRetVal->ErrorCode = ret;
            }
        }
        else
        {
            CcspTraceWarning(("%s: Received an invalid subdoc: %s\n",__FUNCTION__, ni->subdoc_name));
            execRetVal->ErrorCode = SUBDOC_NOT_SUPPORTED;
        }
    }
    else
    {
        CcspTraceWarning(("%s: Received null subdoc blob\n",__FUNCTION__));
        execRetVal->ErrorCode = NULL_BLOB_EXEC_POINTER;
    }

    return execRetVal;
}

/* Callback function to rollback when Network Intelligence blob execution fails */
int ni_webconfig_rollback()
{
    // return 0 to notify framework when rollback is success
    CcspTraceInfo((" Entering %s \n",__FUNCTION__));

    int ret = 0;

    CcspTraceWarning(("%s: Something went wrong while processing webconfig request\n",__FUNCTION__));

    return ret ;
}

/* Callback function to free webconfig resources */
void ni_webconfig_free_resources(void *arg)
{
    CcspTraceInfo((" Entering %s \n",__FUNCTION__));
    execData *blob_exec_data  = (execData*) arg;

    if ( blob_exec_data != NULL )
    {
        networkintelligencedoc_t *nd = (networkintelligencedoc_t *) blob_exec_data->user_data ;

        if ( nd != NULL )
        {
            networkintelligencedoc_destroy(nd);
        }

        AnscFreeMemory (blob_exec_data);
        blob_exec_data = NULL ;
    }
}
