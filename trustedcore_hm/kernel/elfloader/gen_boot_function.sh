#!/bin/bash
# function belong to gen_boot_image.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

function pad8_name()
{
	name="$1"
	padnum=$(expr \( 8 - \( \( length "${name}" \) + 1 \) % 8 \) % 8)
	if [ "${padnum}" == 0 ];
	then
		echo "$name"
		return 0
	fi
	padstr=$(printf "%-${padnum}s" '#')
	padstr=${padstr// /'#'}
	echo "${name}""${padstr}"
	return 0;
}

function check_files()
{
	image="$1"
	if [ ! -e "${image}" ]; then
		echo "File '${image}' does not exist."
		exit 1
	else
		# print kernel image if verbosity is turned on.
		if [ 0"${V}" -ge 2 ]; then
			echo "Using ${image} as kernel image";
		fi
	fi
}

fail() {
    echo "(failed)" >&2
    [ -n "${TEMP_DIR}" ] && rm -rf "${TEMP_DIR}"; exit 1
}

