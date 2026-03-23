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
#define _GNU_SOURCE
#include <string.h>

#ifdef __GNUC__
#if (!defined _NO_EXECINFO_H_)
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#include "stdlib.h"
#include "webconfig_framework.h"
#include "safec_lib_common.h"
#include <sys/stat.h>
#include "syscfg/syscfg.h"
#include <ev.h>
#include <pthread.h>
#define MAX_SUBSYSTEM_SIZE 32

#define ADVSEC_CCSP_INIT_FILE_BOOTUP "/tmp/advsec_ccsp_initialized_bootup"
#define ADVSEC_CUJO_AGENT_ROOT_PRIV "/tmp/advsec_cujo_agent_root_priv"
#define BLOCKLIST_FILE "/opt/secure/Blocklist_file.txt"
#define ADVSEC_AGENT_PROC_NAME "cujo-agent"
#define NUM_SUBSYSTEM_TYPES (sizeof(gSubsystem_type_table)/sizeof(gSubsystem_type_table[0]))

/* Log rotation definitions */
#define ADVSEC_AGENT_LOG_PATH "/rdklogs/logs/agent.txt"
#define ADVSEC_LOG_SIZE_LIMIT 2097152  /* 2MB */
#define ADVSEC_LOGLEVEL_DEBUG 4        /* Debug mode */
#define ADVSEC_SYSCFG_LOGLEVEL "Advsecurity_LogLevel"

/* Global libev loop and thread for log rotation monitoring */
static struct ev_loop *g_log_rotation_ev_loop = NULL;
static ev_stat g_log_rotation_stat;
static pthread_t g_log_rotation_thread;

PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController      = NULL;
PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm  = NULL;
PCCSP_FC_CONTEXT                pAdvSecFcContext           = (PCCSP_FC_CONTEXT            )NULL;
PCCSP_CCD_INTERFACE             pAdvSecCcdIf               = (PCCSP_CCD_INTERFACE         )NULL;
PCCC_MBI_INTERFACE              pTadMbiIf               = (PCCC_MBI_INTERFACE          )NULL;
char                            g_Subsystem[MAX_SUBSYSTEM_SIZE]         = {0};
BOOL                            g_bActive               = FALSE;

int consoleDebugEnable = 0;
FILE* debugLogFile;

enum subsytemType_e {
    SUBSYS,
    C,
    DEBUG,
    LOGFILE,
};


typedef struct gSubsystem_pair{
  char                 *name;
  enum subsytemType_e   type;
} GSUBSYSTEM_PAIR;

GSUBSYSTEM_PAIR gSubsystem_type_table[] = {
  { "-subsys",     SUBSYS  },
  { "-c",          C       },
  { "-DEBUG",      DEBUG   },
  { "-LOGFILE",    LOGFILE }
};

int get_gSubsystem_type_from_name(char *name, enum subsytemType_e *type_ptr)
{
  errno_t rc = -1;
  int ind = -1;
  unsigned int i = 0;
  size_t strsize = 0;

  if((name == NULL) || (type_ptr == NULL))
     return 0;

  strsize = strlen(name);

  for (i = 0 ; i < NUM_SUBSYSTEM_TYPES ; ++i)
  {
      rc = strcmp_s(name, strsize, gSubsystem_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = gSubsystem_type_table[i].type;
          return 1;
      }
  }
  return 0;
}


int  cmd_dispatch(int  command)
{
    char*                           pParamNames[]      = {"Device.IP.Diagnostics.IPPing."};
    parameterValStruct_t**          ppReturnVal        = NULL;
    int                             ulReturnValCount   = 0;
    int                             i                  = 0;
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

    switch ( command )
    {
            case	'e' :

#ifdef _ANSC_LINUX
                CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];
                errno_t                         rc = -1;

                rc = sprintf_s(CName, sizeof(CName), "%s%s", g_Subsystem, CCSP_COMPONENT_ID_ADVSEC);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                    return -1;
                }

                returnStatus = ssp_AdvsecMbi_MessageBusEngage
                               ( 
                                   CName,
                                   CCSP_MSG_BUS_CFG,
                                   CCSP_COMPONENT_PATH_ADVSEC
                               );
                if(returnStatus != ANSC_STATUS_SUCCESS)
                     return -1;
            }

#endif

                returnStatus = ssp_create_advsec();
                if(returnStatus != ANSC_STATUS_SUCCESS)
                     return -1;
                returnStatus = ssp_engage_advsec();
                if(returnStatus != ANSC_STATUS_SUCCESS)
                     return -1;
                g_bActive = TRUE;

                CcspTraceInfo(("AdvSec Module loaded successfully...\n"));

            break;

            case    'r' :

            CcspCcMbi_GetParameterValues
                (
                    DSLH_MPA_ACCESS_CONTROL_ACS,
                    pParamNames,
                    1,
                    &ulReturnValCount,
                    &ppReturnVal,
                    NULL
                );



            for ( i = 0; i < ulReturnValCount; i++ )
            {
                CcspTraceWarning(("Parameter %d name: %s value: %s \n", i+1, ppReturnVal[i]->parameterName, ppReturnVal[i]->parameterValue));
            }

			break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':

                ssp_cancel_advsec();

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#if (!defined _COSA_SIM_) && (!defined _NO_EXECINFO_H_)
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        int fd;
        const char* path = "/nvram/advsecssp_backtrace";
        fd = open(path, O_RDWR | O_CREAT);
        if (fd < 0)
        {
            CcspTraceError(("failed to open backtrace file: %s", path));
            return;
        }

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, fd );
        close(fd);

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
                CcspTraceInfo(("%s\n", funcNames[i] ));

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

#if defined(_ANSC_LINUX)
static void daemonize(void) {
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceError(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceError(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}

//	chdir("/");


#ifndef  _DEBUG

	int fd;
	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceError(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceWarning(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGPIPE received!\n"));
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceError(("Signal %d received, exiting!\n", sig));
    	exit(0);
    }

}

#endif

BOOL isCujoBlocklisted()
{
    BOOL ret = false;
    FILE *fp = NULL;
    int len = 0;
    char *process_name = ADVSEC_AGENT_PROC_NAME;
    char *buf = NULL;
    fp = fopen(BLOCKLIST_FILE, "r");
    if(fp == NULL)
    {
        return ret;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    /* CID 255483: Argument cannot be negative */
    if(len == -1)
    {
        fclose(fp);
        return ret;
    }
    fseek(fp, 0, SEEK_SET);
    buf = (char*)malloc(sizeof(char) * (len + 1));
    if (buf != NULL)
    {
        memset(buf, 0, (sizeof(char) * (len + 1)));
        /* CID 255486: Ignoring number of bytes read */
        int result = fread(buf, 1, len, fp);
        if (result != len)
        {
            CcspTraceError(("Failed to read file %s:%d\n", __FUNCTION__, __LINE__));
            free(buf);
            buf = NULL;
            fclose(fp);
            return ret;
        }
        else
        {
            buf[result] = '\0';
        }
    }
    else
    {
        CcspTraceError(("Memory allocation failed for buffer %s:%d\n", __FUNCTION__, __LINE__));
    }
    fclose(fp);

    if(buf != NULL)
    {
        /* CID 255468: Resource leak */
        if(strlen(buf) != 0)
        {
            if(strcasestr(buf,process_name) != NULL)
            {
                CcspTraceInfo(("process[%s] is found in blocklist, thus process runs in Root mode\n", process_name));
                ret = true;
            }
        }
        free(buf);
        buf = NULL;
    }
    return ret;
}

void drop_root(void)
{
    FILE *fp = NULL;
    BOOL blocklist_ret = false;
    blocklist_ret = isCujoBlocklisted();
    if(blocklist_ret)
    {
        CcspTraceInfo(("NonRoot feature is disabled\n"));
        if ((fp = fopen(ADVSEC_CUJO_AGENT_ROOT_PRIV, "w")))
        {
            fclose(fp);
        }
        else
        {
            CcspTraceError(("File creation failed %s:%d\n", __FUNCTION__, __LINE__));
        }
    }
    else
    {
        CcspTraceInfo(("NonRoot feature is enabled, dropping root privileges for cujo-agent process\n"));
    }
}

/**
 * @brief Check if debug logging is enabled for cujo-agent
 * @return 1 if debug logging is enabled, 0 otherwise
 */
static int is_debug_logging_enabled(void)
{
    char log_level_str[32] = {0};
    int log_level = 0;
    
    if (syscfg_get(NULL, ADVSEC_SYSCFG_LOGLEVEL, log_level_str, sizeof(log_level_str)) == 0)
    {
        log_level = atoi(log_level_str);
        /* DEBUG (4) means debug logging is enabled */
        if (log_level >= ADVSEC_LOGLEVEL_DEBUG)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Check agent.txt size and truncate if file >= 2MB in debug mode
 * This prevents log flooding when debug mode is enabled
 * @param file_size Current size of the file
 */
static void rotate_agent_log_if_needed(off_t file_size)
{
    FILE *fp = NULL;
    
    if (!is_debug_logging_enabled())
    {
        return;
    }
    
    if (file_size >= ADVSEC_LOG_SIZE_LIMIT)
    {
        CcspTraceInfo(("agent.txt size exceeded 2MB (%ld bytes) in debug mode, truncating...\n", (long)file_size));
        
        fp = fopen(ADVSEC_AGENT_LOG_PATH, "w");
        if (fp)
        {
            fprintf(fp, "[%s] Log rotated - debug mode enabled, file exceeded 2MB\n", __FUNCTION__);
            fclose(fp);
            CcspTraceInfo(("agent.txt successfully truncated\n"));
        }
        else
        {
            CcspTraceError(("Failed to truncate agent.txt: %s\n", strerror(errno)));
        }
    }
}

/**
 * @brief libev stat callback triggered when agent.txt file changes
 * @param loop The event loop
 * @param w The stat watcher
 * @param revents Event flags
 */
static void log_rotation_stat_cb(struct ev_loop *loop, ev_stat *w, int revents)
{
    (void)loop;    
    (void)revents;
    
    if (w->attr.st_nlink > 0)
    {
        rotate_agent_log_if_needed(w->attr.st_size);
    }
}

/**
 * @brief Thread function for log rotation monitoring
 * Runs its own libev event loop in a separate thread
 */
static void* log_rotation_thread_func(void *arg)
{
    (void)arg; 
    
    g_log_rotation_ev_loop = ev_loop_new(0);
    if (!g_log_rotation_ev_loop)
    {
        CcspTraceError(("Failed to create log rotation event loop\n"));
        return NULL;
    }
    
    /* Initialize ev_stat to monitor agent.txt file for changes */
    ev_stat_init(&g_log_rotation_stat, log_rotation_stat_cb, ADVSEC_AGENT_LOG_PATH, 0.0);
    
    ev_stat_start(g_log_rotation_ev_loop, &g_log_rotation_stat);
    
    CcspTraceInfo(("Log rotation monitoring thread started (using ev_stat on %s)\n", 
                   ADVSEC_AGENT_LOG_PATH));
    
    ev_run(g_log_rotation_ev_loop, 0);
    
    CcspTraceInfo(("Log rotation monitoring thread exiting\n"));
    return NULL;
}

/**
 * @brief Initialize log rotation monitoring thread
 */
static void init_log_rotation_monitoring(void)
{
    int err;
    
    err = pthread_create(&g_log_rotation_thread, NULL, log_rotation_thread_func, NULL);
    if (err != 0)
    {
        CcspTraceError(("Failed to create log rotation thread: %d\n", err));
    }
    else
    {
        CcspTraceInfo(("Log rotation monitoring thread created successfully\n"));
    }
}

/**
 * @brief Cleanup libev resources and stop thread
 */
static void cleanup_log_rotation_monitoring(void)
{
    if (g_log_rotation_ev_loop)
    {
        ev_stat_stop(g_log_rotation_ev_loop, &g_log_rotation_stat);
        ev_break(g_log_rotation_ev_loop, EVBREAK_ALL);
        
        /* Note: pthread_join not used here to avoid blocking on exit */
        /* The thread will exit when the event loop breaks */
        
        ev_loop_destroy(g_log_rotation_ev_loop);
        g_log_rotation_ev_loop = NULL;
        CcspTraceInfo(("Log rotation monitoring stopped\n"));
    }
}

int main(int argc, char* argv[])
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    int                             cmdChar            = 0;
    BOOL                            bRunAsDaemon       = TRUE;
    int                             idx                = 0;
    errno_t                         rc                 = 1;
    enum subsytemType_e             type;
    int                             ret                = 0;

    debugLogFile = stderr;
#if defined(_DEBUG) && defined(_COSA_SIM_)
    AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);
#endif

    for (idx = 1; idx < argc; idx++)
    {
        /* get the susbsytem type based on the command line argurments */

        if(get_gSubsystem_type_from_name(argv[idx], &type))
        {
             if (type  == SUBSYS)
             {
                  /* Coverity Fix  CID:135431 STRING_SIZE */
                  if( ( (idx+1) < argc  ) && ( strlen(argv[idx + 1]) < sizeof(g_Subsystem) ) )
                  {
                       rc = strcpy_s(g_Subsystem, sizeof(g_Subsystem), argv[idx+1]);
                       if(rc != EOK)
                       {
                           ERR_CHK(rc);
                           CcspTraceError(("Error in copying argv[idx+1] to g_Subsystem\n"));
                           exit(0);
                       }
                  }
                  else
                  {
                       CcspTraceWarning(("idx + 1 exceeds argc  \n"));  
                       exit(0);
                  }
             }
             else if (type == C)
             {
                  bRunAsDaemon = FALSE;
             }
             else if (type == DEBUG)
             {
                  consoleDebugEnable = 1;
                  CcspTraceInfo(("DEBUG ENABLE ON \n"));
             }
             else if (type == LOGFILE)
             {
                  if( (idx+1) < argc )
                  {
                      // We assume argv[1] is a filename to open
                      FILE *fp = fopen( argv[idx + 1], "a+" );

                      /* fopen returns 0, the NULL pointer, on failure */
                      if (!fp)
                      {
                           CcspTraceWarning(("Cannot open -LOGFILE %s\n", argv[idx+1]));
                      }
                      else
                      {
                           debugLogFile = fp;
                           fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
                      }
                  }
                  else
                  {
                       CcspTraceWarning(("Invalid Entry for -LOGFILE input \n" ));
                  }
             }
        }          
    }

    /* Set the global pComponentName */
    pComponentName = CCSP_COMPONENT_NAME_ADVSEC;

#ifdef   _DEBUG
    /*AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);*/
#endif

#if  defined(_ANSC_WINDOWSNT)

    AnscStartupSocketWrapper(NULL);

    display_info();

    ret = cmd_dispatch('e');
    if(ret != 0)
    {
       CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
       exit(0);
    }

    while ( cmdChar != 'q' )
    {
        cmdChar = getchar();

        ret = cmd_dispatch(cmdChar);
        if(ret != 0)
        {
            CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
            exit(0);
        }
    }
#elif defined(_ANSC_LINUX)
    drop_root();
    if ( bRunAsDaemon )
        daemonize();

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    ret = cmd_dispatch('e');
    if(ret != 0)
    {
        CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
        exit(0);
    }

    check_component_crash(ADVSEC_CCSP_INIT_FILE_BOOTUP);

    CcspTraceInfo(("ADVSEC:----------------------touch /tmp/advsec_ccsp__initialized_bootup-------------------\n"));
    ret = creat(ADVSEC_CCSP_INIT_FILE_BOOTUP,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(ret < 0)
    {
        CcspTraceError(("Exit error - Error in copying init_file  %s:%d\n", __FUNCTION__, __LINE__));
        exit(0);
    }

    /* Initialize libev-based log rotation monitoring */
    init_log_rotation_monitoring();

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            sleep(30);
            ret = cmd_dispatch(cmdChar);
            if(ret != 0)
            {
                CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
                exit(0);
            }
        }
    }
#endif

    if ( g_bActive )
    {
        returnStatus = ssp_cancel_advsec();
        if(returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("Exit error - ssp_cancel_advsec() failed %s:%d\n", __FUNCTION__, __LINE__));
            exit(0);
        }

        g_bActive = FALSE;
    }

    /* Cleanup libev resources */
    cleanup_log_rotation_monitoring();

    return 0;
}


