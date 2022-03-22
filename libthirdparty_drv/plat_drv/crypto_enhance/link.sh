#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
set -e

root_path=$(dirname "$0")
pal_path="host/include/pal"
hieps_pal_path="../../../../../../../../../../../hisi/confidential/hieps/crypto/libcrypto/host/include/pal"
sec_inc="libseceng/include"
hieps_sec_inc="../../../../../../../../../../hisi/confidential/hieps/crypto/libcrypto/include"
hieps_agent="driver/agent/include"
link_params=(
	"$pal_path/pal_errno.h"					"$hieps_pal_path/pal_errno.h"
	"$pal_path/pal_libc.h"					"$hieps_pal_path/pal_libc.h"  		
	"$pal_path/pal_log.h"					"$hieps_pal_path/pal_log.h"			
	"$pal_path/pal_timer.h"					"$hieps_pal_path/pal_timer.h"		
	"$pal_path/pal_types.h"					"$hieps_pal_path/pal_types.h"
	"$sec_inc/api"							"$hieps_sec_inc/api"				
	"$sec_inc/common"						"$hieps_sec_inc/common"				
	"$sec_inc/hal"							"$hieps_sec_inc/hal"				
	"$hieps_agent/hieps_seceng_errno.h"		"../../../../../../../../../../../hisi/confidential/hieps/include/errno.h"
	"$hieps_agent/hieps_run_func.h"			"../../../../../../../../../../../hisi/confidential/hieps/driver/cdrm/run_func.h"
	"$hieps_agent/soc_baseaddr_interface.h"	"../../../../../../../../../../../hisi/confidential/hieps/include/soc_interface/kirin990_es/soc_baseaddr_interface.h"
)

if [ "1" == "$1" ]; then
    link_shell="cp -rf"
else
	link_shell="ln -sFT"
fi
cmd_params=($link_shell)
cmd_key="${cmd_params[0]}"
for ((i=0;i<${#link_params[@]};i++));do
	if [ "cp" == "$cmd_key" ]; then
		cmd="$link_shell $root_path/$(dirname ${link_params[$i]})/${link_params[$i + 1]} $root_path/${link_params[$i]}"
	else
		cmd="$link_shell ${link_params[$i + 1]} $root_path/${link_params[$i]}"
	fi

	echo "rm -rf $root_path/${link_params[$i]}"
	rm -rf "$root_path/${link_params[$i]}"
	$cmd
	if [ $? -ne 0 ]
	then
		exit 1
    else
        echo "$cmd"
    fi
	let i=i+1
done
echo -e "\e[0;31mdone\e[0m"
