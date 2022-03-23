#!/bin/bash
# Secure img signature.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

plat="$1"

if [ -z "${plat}" ];then
	echo "usage: ""$0"" <platform>"
	echo "platform: kirin970, kirin980, kirin710, hi3660..."
	exit
fi

account_check()
{
    local onlinename
    local onlinepasswd
    echo "input you domain account for certificate."
    echo "accout:"
    read onlinename
    stty -echo
    echo "passwd:"
    read onlinepasswd
    stty echo
    export ONLINE_USERNAME="$onlinename"
    export ONLINE_PASSWD="$onlinepasswd"
}


if [ -z "${ONLINE_USERNAME}" ] || [ -z "${ONLINE_PASSWD}" ];then
	account_check
fi

# Sign trustedcore.img
echo "Sign ${plat} trustedcore.img"

TOPDIR=$(pwd)
echo "$TOPDIR"
HMSDK="${TOPDIR}"
SIGNTOOL=vrl_creater_for_online
SIGNTOOLDIR="${TOPDIR}"/../../../../thirdparty/hisi/"${SIGNTOOL}"
WORKINGDIR="${HMSDK}"/output/sectrustedcore_hm

if [ -f "${HMSDK}"/output/stage/trustedcore.img ]; then
	[ -n "${WORKINGDIR}" ] && rm -rf "${WORKINGDIR}"
	mkdir -p "${WORKINGDIR}"
	cp -af "${SIGNTOOLDIR}" "${WORKINGDIR}"
	cp "${HMSDK}"/output/stage/trustedcore.img "${WORKINGDIR}"/"${SIGNTOOL}"

	cd "${WORKINGDIR}"/"${SIGNTOOL}"/utils/src/secure_boot_utils; \
		make clean; \
		make install_lib; \
		make install_sbu

	cd "${WORKINGDIR}"/"${SIGNTOOL}"
	./create_cert.sh trustedcore trustedcore.img "${plat}"
	cp sec_trustedcore.img "${TOPDIR}"
	echo "sign ""${plat}"" image success!"
	ls -l "${TOPDIR}"/sec_trustedcore.img
	cd "${HMDIR}"

	[ -n "${WORKINGDIR}" ] && rm -rf "${WORKINGDIR}"
else
	echo "${HMSDK}"/output/stage/trustedcore.img not exist!!!
fi
