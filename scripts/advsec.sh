#!/bin/bash
##########################################################################
#
# Copyright 2018 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0
##########################################################################
source /etc/device.properties
source /etc/log_timestamp.sh
source /usr/bin/cujo-agent-sh-env

export RUNTIME_DIR="/usr"
if [ "$DEVICE_MODEL" = "TCHXB3" ]; then
    export RUNTIME_DIR="/tmp/cujo_dnld/usr"
fi

CUJO_AGENT="cujo-agent"
CUJO_AGENT_SH="cujo-agent --ctl"
CUJO_AGENT_LOG="CujoAgent"
CUJO_AGENT_USER_NAME="_cujo-agent"
CUJO_AGENT_STATUS="cujo-agent-status"

if [ "$BOX_TYPE" = "XB3" ] || [ "$BOX_TYPE" = "XF3" ]; then
    CUJO_AGENT="rabid"
    CUJO_AGENT_SH="rabidsh"
    CUJO_AGENT_LOG="Rabid"
    CUJO_AGENT_USER_NAME="_rabid"
fi

export APPLIANCE_MODE="EMBEDDED"
export NFLUA_MODULE_PATH="/lib/modules/$(uname -r)/nflua.ko"
export LUACONNTRACK_MODULE_PATH="/lib/modules/$(uname -r)/luaconntrack.ko"
export LUADATA_MODULE_PATH="/lib/modules/$(uname -r)/luadata.ko"
export LUAJSON_MODULE_PATH="/lib/modules/$(uname -r)/luajson.ko"
export LUNATIK_MODULE_PATH="/lib/modules/$(uname -r)/lunatik.ko"
export LUAPUMA_MODULE_PATH="/lib/modules/$(uname -r)/luapuma.ko"
export PUMASTATS_MODULE_PATH="/lib/modules/$(uname -r)/pumastats.ko"
export LUAKCRYPTO_MODULE_PATH="/lib/modules/$(uname -r)/luakcrypto.ko"
export NF_NETLINK_QUEUE_MODULE_PATH="/lib/modules/$(uname -r)/kernel/net/netfilter/nfnetlink_queue.ko"
export NF_NETLINK_QUEUE_PROC_PATH="/proc/self/net/netfilter/nfnetlink_queue"

export RW_DIR="/tmp"
export INFO_DIR="${RW_DIR}/advsec"
export CONFIG_DIR="${INFO_DIR}/config"
export ADVSEC_CONFIG_PARAMS_PATH="/tmp/advsec_config_params"

export DAEMONS_HIBERNATING=/tmp/advsec_daemons_hibernating
export SOFTFLOWD_ENABLE=/tmp/advsec_softflowd_enable
export SAFEBRO_ENABLE=/tmp/advsec_safebro_enable
export AGENT_HIBERNATION_PRINT=ADVSEC_AGENT_HIBERNATION_STATUS:
export ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS_PRINT=ADV_PARENTAL_CONTROL_NUMBER_OF_ACTIVE_MACS:
export ADVSEC_INITIALIZING=/tmp/advsec_initializing
export ADVSEC_INITIALIZED=/tmp/advsec_initialized
export ADVSEC_AGENT_SHUTDOWN=/tmp/advsec_agent_shutdown
export ADVSEC_AGENT_SHUTDOWN_COMPLETE=/tmp/advsec_agent_shutdown_complete
export ADVSEC_DF_ENABLED_PATH=/tmp/advsec_df_enabled
export ADV_PARENTAL_CONTROL_PATH=/tmp/adv_parental_control
export PRIVACY_PROTECTION_PATH=/tmp/adv_privacy_protection
export ADVSEC_APPBLOCK_PATH=/tmp/advsec_appblocker_enabled
export ADVSEC_AGENT_LOG_PATH=/rdklogs/logs/agent.txt
export ADVSEC_LOOKUP_EXCEED_COUNT_FILE="/tmp/advsec_lkup_exceed_cnt"
export ADVSEC_NFLUA_LOADED=/tmp/advsec_nflua_loaded
export ADVSEC_CLOUD_IP=/tmp/advsec_cloud_ipv4
export ADVSEC_CLOUD_HOST=/tmp/advsec_cloud_host
export ADVSEC_ASSOC_SUCCESS=/tmp/advsec_assoc_success
export ADVSEC_IPSETLIST_CREATED=/tmp/advsec_ipsetlist_created
export ADVSEC_DEVICE_CERT=/tmp/cujo_xpki_cert.pem
export ADV_PARENTAL_CONTROL_ACTIVEMACSFILE=/tmp/activemacs
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export ADVSEC_DF_ICMPv6_ENABLED_PATH=/tmp/advsec_df_icmpv6_enabled
fi
export ADVSEC_WS_DISCOVERY_ENABLED_PATH=/tmp/advsec_ws_discovery_enabled
export ADVSEC_RAPTR_ENABLED_PATH=/tmp/advsec_raptr_enabled
export ADVSEC_USERSPACE_ENABLED_PATH=/tmp/advsec_userspace_enabled
export ADVSEC_CUJOTRACER_ENABLED_PATH=/tmp/advsec_cujotracer_enabled
export ADVSEC_CUJOTELEMETRY_ENABLED_PATH=/tmp/advsec_cujotelemetry_enabled
export ADVSEC_WIFIDATACOLLECTION_ENABLED_PATH=/tmp/advsec_wifidatacollection_enabled
export ADVSEC_LEVL_ENABLED_PATH=/tmp/advsec_levl_enabled
export ADVSEC_AGENT_ENABLED_PATH=/tmp/advsec_agent_enabled
export ADVSEC_SAFEBROWSING_ENABLED_PATH=/tmp/advsec_safebrowsing_enabled
export ADVSEC_CUJOTELEMETRYWIFIFP_ENABLED_PATH=/tmp/advsec_cujotelemetrywififp_enabled
export ADVSEC_WIFIDCL_INIT_PATH=/tmp/advsec_wifidcl_init

export CUJO_AGENT_RULES_V4_PATH=/tmp/.cujo-agent-rules
export CUJO_AGENT_RULES_V6_PATH=/tmp/.cujo-agent-rules_v6

export DF_ENABLED=`syscfg get Advsecurity_DeviceFingerPrint`
export ADVSEC_SB_ENABLED=`syscfg get Advsecurity_SafeBrowsing`
export ADVSEC_SF_ENABLED=`syscfg get Advsecurity_Softflowd`
export ADV_PC_ENABLED=`syscfg get Adv_PCActivate`
export PRIVACY_PROTECTION_ENABLED=`syscfg get Adv_PPActivate`
export ADV_PC_RFC_ENABLED=`syscfg get Adv_PCRFCEnable`
export PRIVACY_PROTECTION_RFC_ENABLED=`syscfg get Adv_PrivProtRFCEnable`
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export DF_ICMPv6_RFC_ENABLED=`syscfg get Adv_DFICMPv6RFCEnable`
fi
export ADVSEC_OTM_RFC_ENABLED=`syscfg get Adv_AdvSecOTMRFCEnable`
export ADVSEC_WS_DISCOVERY_RFC_ENABLED=`syscfg get Adv_WSDisAnaRFCEnable`
export ADVSEC_RAPTR_RFC_ENABLED=`syscfg get Adv_RaptrRFCEnable`
export ADVSEC_USERSPACE_RFC_ENABLED=`syscfg get Adv_AdvSecUserSpaceRFCEnable`
export ADVSEC_CUJOTRACER_RFC_ENABLED=`syscfg get Adv_AdvSecCujoTracerRFCEnable`
export ADVSEC_CUJOTELEMETRY_RFC_ENABLED=`syscfg get Adv_AdvSecCujoTelemetryRFCEnable`
export ADVSEC_WIFIDATACOLLECTION_RFC_ENABLED=`syscfg get Adv_WifiDataCollectionRFCEnable`
export ADVSEC_LEVL_RFC_ENABLED=`syscfg get Adv_LevlRFCEnable`
export ADVSEC_AGENT_RFC_ENABLED=`syscfg get Adv_AdvSecAgentRFCEnable`
export ADVSEC_SAFEBROWSING_RFC_ENABLED=`syscfg get Adv_AdvSecSafeBrowsingRFCEnable`
export ADVSEC_CUJOTELEMETRYWIFIFP_RFC_ENABLED=`syscfg get Adv_AdvSecCujoTelemetryWiFiFPRFCEnable`

export ADV_PARENTAL_CONTROL_ACTIVATED_LOG=ADVANCED_PARENTAL_CONTROL_ACTIVATED
export ADV_PARENTAL_CONTROL_DEACTIVATED_LOG=ADVANCED_PARENTAL_CONTROL_DEACTIVATED
export PRIVACY_PROTECTION_ACTIVATED_LOG=PRIVACY_PROTECTION_ACTIVATED
export PRIVACY_PROTECTION_DEACTIVATED_LOG=PRIVACY_PROTECTION_DEACTIVATED
export PRIVACY_PROTECTION_RFC_ENABLED_LOG=PRIVACY_PROTECTION_RFC_STATUS_ENABLED
export PRIVACY_PROTECTION_RFC_DISABLED_LOG=PRIVACY_PROTECTION_RFC_STATUS_DISABLED
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
    export AGENT_RUNNING_AS_NON_ROOT_LOG=CUJO_AGENT_RUNNING_AS_NON_ROOT
    export AGENT_RUNNING_AS_ROOT_LOG=CUJO_AGENT_RUNNING_AS_ROOT
else
    export AGENT_RUNNING_AS_NON_ROOT_LOG=RABID_RUNNING_AS_NON_ROOT
    export AGENT_RUNNING_AS_ROOT_LOG=RABID_RUNNING_AS_ROOT
fi
if [ "$BOX_TYPE" != "XB3" ] && [ "$BOX_TYPE" != "XF3" ]; then
export DF_ICMPv6_RFC_ENABLED_LOG=DeviceFingerPrintICMPv6.Enabled
export DF_ICMPv6_RFC_DISABLED_LOG=DeviceFingerPrintICMPv6.Disabled
fi
export ADV_OTM_RFC_ENABLE_LOG=ADVANCE_SECURITY_OTM_ENABLED
export ADV_OTM_RFC_DISABLE_LOG=ADVANCE_SECURITY_OTM_DISABLED
export ADV_WS_DISCOVERY_RFC_ENABLE_LOG=ADVANCE_SECURITY_WS_DISCOVERY_ENABLED
export ADV_WS_DISCOVERY_RFC_DISABLE_LOG=ADVANCE_SECURITY_WS_DISCOVERY_DISABLED
export ADV_RAPTR_RFC_ENABLE_LOG=ADVANCE_SECURITY_RAPTR_ENABLED
export ADV_RAPTR_RFC_DISABLE_LOG=ADVANCE_SECURITY_RAPTR_DISABLED
export ADV_USERSPACE_RFC_ENABLE_LOG=ADVANCE_SECURITY_USERSPACE_ENABLED
export ADV_USERSPACE_RFC_DISABLE_LOG=ADVANCE_SECURITY_USERSPACE_DISABLED
export ADV_WIFIDATACOLLECTION_RFC_ENABLE_LOG=ADVANCE_SECURITY_WIFIDATACOLLECTION_ENABLED
export ADV_WIFIDATACOLLECTION_RFC_DISABLE_LOG=ADVANCE_SECURITY_WIFIDATACOLLECTION_DISABLED
export ADV_LEVL_RFC_ENABLE_LOG=ADVANCE_SECURITY_LEVL_ENABLED
export ADV_LEVL_RFC_DISABLE_LOG=ADVANCE_SECURITY_LEVL_DISABLED
export ADV_AGENT_RFC_ENABLE_LOG=ADVANCE_SECURITY_AGENT_ENABLED
export ADV_AGENT_RFC_DISABLE_LOG=ADVANCE_SECURITY_AGENT_DISABLED
export ADV_SAFEBROWSING_RFC_ENABLE_LOG=ADVANCE_SECURITY_SAFEBROWSING_IPTABLE_RULES_ENABLED
export ADV_SAFEBROWSING_RFC_DISABLE_LOG=ADVANCE_SECURITY_SAFEBROWSING_IPTABLE_RULES_DISABLED
export ADV_CUJOTELEMETRYWIFIFP_RFC_ENABLE_LOG=ADVANCE_SECURITY_CUJOTELEMETRYWIFIFP_ENABLED
export ADV_CUJOTELEMETRYWIFIFP_RFC_DISABLE_LOG=ADVANCE_SECURITY_CUJOTELEMETRYWIFIFP_DISABLED
export ADV_CUJOTRACER_RFC_ENABLE_LOG=ADVANCE_SECURITY_CUJOTRACER_ENABLED
export ADV_CUJOTRACER_RFC_DISABLE_LOG=ADVANCE_SECURITY_CUJOTRACER_DISABLED
export ADV_CUJOTELEMETRY_RFC_ENABLE_LOG=ADVANCE_SECURITY_CUJOTELEMETRY_ENABLED
export ADV_CUJOTELEMETRY_RFC_DISABLE_LOG=ADVANCE_SECURITY_CUJOTELEMETRY_DISABLED

export ADVSEC_SAFEBRO_SETTING="${RW_DIR}/safebro.json"

if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
    export CC_PLATFORM_TYPE="PUMA"
fi

advsec_is_agent_installed()
{
    if [ -e ${RUNTIME_DIR}/bin/launch-${CUJO_AGENT} ]; then
        echo "YES"
    else
        echo "NO"
    fi
}

advsec_start_agent()
{
    ADV_AGENT_PID=`advsec_is_alive ${CUJO_AGENT}`
    if [ "${ADV_AGENT_PID}" = "" ] ; then
        echo_t "Starting ${CUJO_AGENT_LOG}..."
        echo_t "[ADVSEC_LOG_START]" >> $ADVSEC_AGENT_LOG_PATH
        ${RUNTIME_DIR}/bin/launch-${CUJO_AGENT} start 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        sysctl -w net.core.optmem_max=65536
    else
        echo_t '${CUJO_AGENT_LOG} is already running...'
    fi
}

advsec_wait_for_agent()
{
    if [ "$1" != "" ]; then
        TIMEOUT=$1
    else
        TIMEOUT=60
    fi
    sleep $TIMEOUT
    ${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e "return"
    EXIT_STATUS=$?
    RETRY_CNT=5
    while [ ${EXIT_STATUS} -ne 0 ] && [ ${RETRY_CNT} -gt 0 ]; do
        echo_t "${CUJO_AGENT_LOG} is not active...keep waiting...iteration=$RETRY_CNT"
        sleep 5s
        ${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e "return"
        EXIT_STATUS=$?
        RETRY_CNT=$(expr $RETRY_CNT - 1)
    done
}

advsec_agent_start_fp()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "fingerprint" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADVSEC_DF_ENABLED_PATH}
}

advsec_agent_start_sb()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "safebro.reputation" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${SAFEBRO_ENABLE}
}

advsec_agent_start_sf()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "tcptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${SOFTFLOWD_ENABLE}
    if [ ! -e ${ADVSEC_APPBLOCK_PATH} ]; then
        start_iot_blocker
    fi
}

advsec_stop_agent()
{
    ${RUNTIME_DIR}/bin/launch-${CUJO_AGENT} stop 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

advsec_agent_stop_fp()
{
    if [ -e ${ADVSEC_DF_ENABLED_PATH} ]; then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "fingerprint" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADVSEC_DF_ENABLED_PATH}
    fi
}

advsec_agent_stop_sb()
{
    if [ -e ${SAFEBRO_ENABLE} ]; then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "safebro.reputation" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${SAFEBRO_ENABLE}
    fi
}

advsec_agent_stop_sf()
{
    if [ -e ${SOFTFLOWD_ENABLE} ]; then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "tcptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${SOFTFLOWD_ENABLE}
        if [ ! -e ${ADVSEC_APPBLOCK_PATH} ]; then
            stop_iot_blocker
        fi
    fi
}

start_adv_parental_control()
{
    if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "SR203" ] || [ "$MODEL_NUM" = "VTER11QEL" ]; then
        sysctl -w net.netfilter.nf_conntrack_acct=1
    fi

    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "apptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADV_PARENTAL_CONTROL_PATH}
}

stop_adv_parental_control()
{
    if [ "$MODEL_NUM" = "TG1682G" ] || [ "$MODEL_NUM" = "DPC3941" ] || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "SR203" ] || [ "$MODEL_NUM" = "VTER11QEL" ]; then
        sysctl -w net.netfilter.nf_conntrack_acct=0
    fi
    if [ -e ${ADV_PARENTAL_CONTROL_PATH} ];then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "apptracker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADV_PARENTAL_CONTROL_PATH}
    fi
}

start_privacy_protection()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "safebro.trackerblock" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${PRIVACY_PROTECTION_PATH}
}

stop_privacy_protection()
{
    if [ -e ${PRIVACY_PROTECTION_PATH} ];then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "safebro.trackerblock" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${PRIVACY_PROTECTION_PATH}
    fi
}

start_app_blocker()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "appblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
    touch ${ADVSEC_APPBLOCK_PATH}
    if [ ! -e ${SOFTFLOWD_ENABLE} ]; then
        start_iot_blocker
    fi
}

stop_app_blocker()
{
    if [ -e ${ADVSEC_APPBLOCK_PATH} ]; then
        ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "appblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
        rm ${ADVSEC_APPBLOCK_PATH}
        if [ ! -e ${SOFTFLOWD_ENABLE} ]; then
            stop_iot_blocker
        fi
    fi
}

start_iot_blocker()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature on "iotblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

stop_iot_blocker()
{
    ${RUNTIME_DIR}/bin/${CUJO_AGENT}-feature off "iotblocker" 2>&1 >> $ADVSEC_AGENT_LOG_PATH
}

advsec_module_load()
{
	sysfs_mount="0"
	if [ "$MODEL_NUM" = "TG1682G" ]; then
		mount -t sysfs none /sys -n
		if [ "$?" = "0" ]; then
			sysfs_mount="1"
		fi
	fi

	if [ ! -f $NF_NETLINK_QUEUE_PROC_PATH ]; then
		echo_t "[ADVSEC] $NF_NETLINK_QUEUE_PROC_PATH not present" >> $ADVSEC_AGENT_LOG_PATH
		echo_t "[ADVSEC] Load nfnetlink_queue kernel module manually" >> $ADVSEC_AGENT_LOG_PATH
		insmod $NF_NETLINK_QUEUE_MODULE_PATH 2>> $ADVSEC_AGENT_LOG_PATH
		STATUS=$?
		if [ ${STATUS} ]; then
			echo_t "[ADVSEC] kernel module nfnetlink_queue successfully loaded" >> $ADVSEC_AGENT_LOG_PATH
		else
                	echo_t "[ADVSEC] Unable to load nfnetlink_queue kernel module" >> $ADVSEC_AGENT_LOG_PATH
		fi
	fi

        if [ "$ADVSEC_USERSPACE_RFC_ENABLED" -eq 0 ]; then
            # unload userspace kernel module - switching from userspace to nflua mode
            if [ "$ADV_PC_RFC_ENABLED" = "1" ]; then
                advsec_kernel_module_unload $PUMASTATS_MODULE_PATH
            fi
            advsec_kernel_module_load $LUNATIK_MODULE_PATH
            advsec_kernel_module_load $LUADATA_MODULE_PATH
            advsec_kernel_module_load $LUAKCRYPTO_MODULE_PATH
            advsec_kernel_module_load $LUAJSON_MODULE_PATH
            advsec_kernel_module_load $LUACONNTRACK_MODULE_PATH
            advsec_kernel_module_load $NFLUA_MODULE_PATH
            advsec_kernel_module_load $LUAPUMA_MODULE_PATH
        else
            # unload nflua kernel modules - switching from nflua to userspace mode
            advsec_kernel_module_unload $NFLUA_MODULE_PATH
            advsec_kernel_module_unload $LUAPUMA_MODULE_PATH
            advsec_kernel_module_unload $LUACONNTRACK_MODULE_PATH
            advsec_kernel_module_unload $LUAJSON_MODULE_PATH
            advsec_kernel_module_unload $LUADATA_MODULE_PATH
            advsec_kernel_module_unload $LUAKCRYPTO_MODULE_PATH
            advsec_kernel_module_unload $LUNATIK_MODULE_PATH
            if [ "$ADV_PC_RFC_ENABLED" = "1" ]; then
                advsec_kernel_module_load $PUMASTATS_MODULE_PATH
            fi
        fi

	if [ "$MODEL_NUM" = "TG1682G" ] && [ "$sysfs_mount" = "1" ]; then
		umount /sys
	fi

	touch ${ADVSEC_NFLUA_LOADED}
}

advsec_module_unload()
{
	rm -f ${ADVSEC_NFLUA_LOADED}
        sysfs_mount="0"
        if [ "$MODEL_NUM" = "TG1682G" ]; then
                mount -t sysfs none /sys -n
                if [ "$?" = "0" ]; then
                        sysfs_mount="1"
                fi
        fi

        if [ "$ADVSEC_USERSPACE_RFC_ENABLED" -eq 0 ]; then
            advsec_kernel_module_unload $NFLUA_MODULE_PATH
            advsec_kernel_module_unload $LUAPUMA_MODULE_PATH
            advsec_kernel_module_unload $LUACONNTRACK_MODULE_PATH
            advsec_kernel_module_unload $LUAJSON_MODULE_PATH
            advsec_kernel_module_unload $LUADATA_MODULE_PATH
            advsec_kernel_module_unload $LUAKCRYPTO_MODULE_PATH
            advsec_kernel_module_unload $LUNATIK_MODULE_PATH
        else
            if [ "$ADV_PC_RFC_ENABLED" = "1" ]; then
                advsec_kernel_module_unload $PUMASTATS_MODULE_PATH
            fi
        fi

	if [ "$MODEL_NUM" = "TG1682G" ] && [ "$sysfs_mount" = "1" ]; then
		umount /sys
	fi
}

advsec_kernel_module_load()
{
    if [ -e $1 ]; then
        insmod $1 2>> $ADVSEC_AGENT_LOG_PATH
        STATUS=$?
        if [ ${STATUS} ]; then
            echo_t "[ADVSEC] NFLua kernel module $1 successfully loaded"  >> $ADVSEC_AGENT_LOG_PATH
        else
            echo_t "[ADVSEC] Unable to load $1 kernel module"  >> $ADVSEC_AGENT_LOG_PATH
        fi
    fi
}

advsec_kernel_module_unload()
{
    if [ -e $1 ]; then
        module_name=$(basename "$1" | cut -d . -f1)
        if lsmod | grep -q "^$module_name"; then
            rmmod $1 2>> $ADVSEC_AGENT_LOG_PATH
            STATUS=$?
            if [ ${STATUS} ]; then
                echo_t "[ADVSEC] kernel module $1 successfully unloaded"  >> $ADVSEC_AGENT_LOG_PATH
            else
                echo_t "[ADVSEC] Unable to unload $1 kernel module"  >> $ADVSEC_AGENT_LOG_PATH
            fi
        fi
    fi
}

advsec_initialize_nfq_ct()
{
    if [ "$MODEL_NUM" = "PX5001" ]; then
            echo_t "Initializing nfq_ct data ..."  >> $ADVSEC_AGENT_LOG_PATH
            conntrack -L >& /dev/null
    fi
}

advsec_agent_create_ipsets()
{
    if [ -f $ADVSEC_RAPTR_ENABLED_PATH ]; then
        raptr set -n | grep ipset | bash
    else
        ipset create cujo_fingerprint hash:mac -exist
        ipset create cujo_iotblock_mac hash:mac -exist
        ipset create cujo_iotblock_ip4 hash:ip family inet -exist
        ipset create cujo_iotblock_ip6 hash:ip family inet6 -exist
    fi
    touch ${ADVSEC_IPSETLIST_CREATED}
}

advsec_agent_flush_ipsets()
{
    ipset flush
    ipset destroy cujo_fingerprint
    ipset destroy cujo_iotblock_mac
    ipset destroy cujo_iotblock_ip4
    ipset destroy cujo_iotblock_ip6
    rm -f ${ADVSEC_IPSETLIST_CREATED}
}

advsec_agent_restart_needed()
{
	result="0"
	#Check for cloud socket connection
	if [ -e ${SOFTFLOWD_ENABLE} ] || [ -e ${ADV_PARENTAL_CONTROL_PATH} ]; then
		if [ -e ${ADVSEC_CLOUD_IP} ] && [ -e ${ADVSEC_ASSOC_SUCCESS} ]; then
			ip_port=`cat ${ADVSEC_CLOUD_IP}`
			if [ "${ip_port}" != "" ]; then
				stat=`sysevent get wan-status`
				if [ "${stat}" = "started" ]; then
					res=`netstat -an | grep ${ip_port} | grep "ESTABLISHED"`
					if [ "${res}" = "" ]; then
						result="1"
						touch ${ADVSEC_AGENT_SHUTDOWN}
						echo_t "[ADVSEC] ${CUJO_AGENT_LOG} is going to restart due to no websocket connection..." >> ${ADVSEC_AGENT_LOG_PATH}
						echo_t "netstat output: $res" >> ${ADVSEC_AGENT_LOG_PATH}
						echo_t "IP_PORT: $ip_port" >> ${ADVSEC_AGENT_LOG_PATH}
					fi
				fi
			fi
		fi
	fi
	echo ${result}
}

advsec_is_alive() {

	if [ "$1" = "${CUJO_AGENT}" ]
	then
		PROCESS_PID=`pidof ${CUJO_AGENT}`
	fi
	echo $PROCESS_PID
}

advsec_stop_process() {
	ADVSEC_RDK_LOG_FILE=""
	echo_t "Stopping process " $1
	if [ "$1" = "${CUJO_AGENT}" ]
	then
		PROCESS_PID=`pidof ${CUJO_AGENT}`
		ADVSEC_RDK_LOG_FILE=$ADVSEC_AGENT_LOG_PATH
	fi
	if [ "$PROCESS_PID" != "" ]; then
		kill -TERM $PROCESS_PID
	fi
	if [ "$ADVSEC_RDK_LOG_FILE" != "" ]; then
		echo_t "[ADVSEC_LOG_STOP]" >> $ADVSEC_RDK_LOG_FILE
	fi
}

advsec_cleanup_config() {
	rm -rf $INFO_DIR

        if [ -e ${ADVSEC_SAFEBRO_SETTING} ]; then
                rm -rf ${ADVSEC_SAFEBRO_SETTING}
        fi

}

advsec_cleanup_config_agent() {
    if [ -e ${ADVSEC_IPSETLIST_CREATED} ]; then
        rm -f ${ADVSEC_IPSETLIST_CREATED}
    fi

    if [ -e $DAEMONS_HIBERNATING ]; then
        rm -f $DAEMONS_HIBERNATING
    fi

    if [ -e ${ADVSEC_ASSOC_SUCCESS} ]; then
        rm -f ${ADVSEC_ASSOC_SUCCESS}
    fi

    if [ -e ${ADVSEC_SAFEBRO_SETTING} ]; then
        rm ${ADVSEC_SAFEBRO_SETTING}
    fi

    if [ -e ${ADV_PARENTAL_CONTROL_ACTIVEMACSFILE} ]; then
        rm ${ADV_PARENTAL_CONTROL_ACTIVEMACSFILE}
    fi

    if [ -e ${ADVSEC_CLOUD_HOST} ]; then
        rm ${ADVSEC_CLOUD_HOST}
    fi

    if [ -e ${ADVSEC_DEVICE_CERT} ]; then
        rm ${ADVSEC_DEVICE_CERT}
    fi

    advsec_cleanup_config
}

advsec_restart_agent() {
    if [ ! -f $ADVSEC_INITIALIZING ]; then
        touch $ADVSEC_INITIALIZING
        if [ "$1" != "" ]; then
            echo_t "[ADVSEC] Restarting ${CUJO_AGENT_LOG} due to $1..." >> ${ADVSEC_AGENT_LOG_PATH}
        else
            echo_t "[ADVSEC] Restarting ${CUJO_AGENT_LOG} due to Selfheal..." >> ${ADVSEC_AGENT_LOG_PATH}
        fi

        advsec_stop_agent

        advsec_cleanup_config_agent

        sleep 5
        if [ ! -e ${ADVSEC_NFLUA_LOADED} ]
        then
                advsec_module_load
        fi

        if [ ! -e ${ADVSEC_IPSETLIST_CREATED} ]
        then
            advsec_agent_create_ipsets
        fi

        advsec_start_agent
        advsec_wait_for_agent 30

        if [ -e ${ADVSEC_DF_ENABLED_PATH} ]
        then
                advsec_agent_start_fp
        fi

        if [ -e ${SAFEBRO_ENABLE} ]
        then
                advsec_agent_start_sb
        fi
        if [ -e ${SOFTFLOWD_ENABLE} ]
        then
                advsec_agent_start_sf
        fi

        if [ -e ${ADV_PARENTAL_CONTROL_PATH} ] && [ "$ADV_PC_RFC_ENABLED" = "1" ]
        then
               start_adv_parental_control
        fi

        if [ -e ${PRIVACY_PROTECTION_PATH} ] && [ "$PRIVACY_PROTECTION_RFC_ENABLED" = "1" ]
        then
               start_privacy_protection
        fi

        rm $ADVSEC_INITIALIZING
    fi
}

advsec_get_agent_group_name() 
{
        agent_pid=`pidof cujo-agent`
        if [ -n "$agent_pid" ]
        then
         agent_uid=`cat /proc/"$agent_pid"/status | grep -i uid | awk '{print $NF}'`
         agentuser=`cat /etc/passwd | grep ":$agent_uid:" | cut -d: -f1`
         echo $agentuser
        fi

}

advsec_agent_loglevel()
{
      get_agentloglevel=`${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e 'return cujo.log:level()'`
      if [ "$get_agentloglevel" != "$1" ]; then
         set_agentloglevel="${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e cujo.log:level($1)"
         ${set_agentloglevel}
         echo_t "${CUJO_AGENT} LogLevel changed from LogLevel-$get_agentloglevel to LogLevel-$1" >> ${ADVSEC_AGENT_LOG_PATH}
      fi
}

advsec_agent_get_safebro_config()
{
    safebro_json=`${RUNTIME_DIR}/bin/${CUJO_AGENT_STATUS} safebro-config`
    echo $safebro_json > ${ADVSEC_SAFEBRO_SETTING}
}

wait_for_lanip()
{
    ip_retry_limit=6
    while [ ${ip_retry_limit} -gt 0 ]; do
        lanipv6addr=`ip -6 a s brlan0 | grep global | cut -d " " -f 6`
        lanipv4addr=`ip -4 a s brlan0 | grep global | cut -d " " -f 6`
        if [ "$lanipv6addr" = "" ] || [ "$lanipv4addr" = "" ]; then
             echo_t "Waiting for LAN ipv6 and ipv4 address..." >> ${ADVSEC_AGENT_LOG_PATH}
             sleep 10
             ip_retry_limit=$(expr $ip_retry_limit - 1)
        else
             echo_t "LAN IPv6 Address: $lanipv6addr and IPv4 Address: $lanipv4addr" >> ${ADVSEC_AGENT_LOG_PATH}
             break
        fi
    done
}

