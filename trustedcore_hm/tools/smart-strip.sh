#!/bin/bash
# Get the elf file, judge 32 or 64, and strip off some symbol information and debugging information to make the file smaller
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

strip_file() {
	STRIP_OPTION="-d -x -p"
	is_elf=$(file "$1" | grep ELF)
	if [ "x${is_elf}" = x ]; then
		# not a ELF file
		return
	fi
	if (echo "$1" | grep '\.so$') ; then
		STRIP_OPTION="-s -p"
	fi
	set +o errexit
	is_arm=$(readelf -h "$1" 2>/dev/null | grep -E "Machine:.*(ARM|AArch64)")
	is_a32=$(readelf -h "$1" 2>/dev/null | grep "Class:.*ELF32")
	is_a64=$(readelf -h "$1" 2>/dev/null | grep "Class:.*ELF64")
	is_obj=$(readelf -h "$1" 2>/dev/null | grep "Type:.*REL")
	if [ "x${is_obj}" != x ]; then
		STRIP_OPTION="-d -p"
	fi
	set -o errexit
	if [ "x${is_arm}" != x ]; then
		IS_A32=0
		IS_A64=0
		if [ "x${is_a32}" != x ]; then
			IS_A32=1
		fi
		if [ "x${is_a64}" != x ]; then
			IS_A64=1
		fi

		ls -l "$1"
		if [ "$IS_A32" = 1 ]; then
			"${STRIP}" ${STRIP_OPTION} "$1"
		fi

		if [ "$IS_A64" = 1 ]; then
			"${STRIP}" ${STRIP_OPTION} "$1"
		fi
		ls -l "$1"
	fi
}

for fn in $*; do
	strip_file "$fn"
done
