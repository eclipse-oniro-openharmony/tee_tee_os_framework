#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2022. All rights reserved.
set -e
COMPARE_IMAGE="$2"

KERNEL_TEXT_BASE=0; echo "kernel text base=${KERNEL_TEXT_BASE}"

PLATFORM_CHOOSE="$1"; echo "platform is ${PLATFORM_CHOOSE}"

CHIP_CHOOSE="$3"; echo "chip is ${CHIP_CHOOSE}"

TEEOS_IMG_ENCRYPT="$4"; echo "TEE IMG encrypt is ${TEEOS_IMG_ENCRYPT}"

if [ "${TEEOS_IMG_ENCRYPT}" ]; then
  echo "TEE IMG encrypt is ${TEEOS_IMG_ENCRYPT}"
else
	echo "Error:there is no input TEEOS_IMG_ENCRYPT Feature"; exit -1
fi

TEEOS_LOG_ENCODE="$5"; echo "TEEOS_LOG_ENCODE is ${TEEOS_LOG_ENCODE}"

IMAGE_LOAD_ADDR=0; echo "IMAGE_LOAD_ADDR is ${IMAGE_LOAD_ADDR}"

CURDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"; echo "CURDIR: ${CURDIR}"

if [[ "${IMAGE_ROOT}" == '' ]]; then
    echo "IMAGE_ROOT must specify"; exit -1;
fi
echo "IMAGE_ROOT: ${IMAGE_ROOT}"

DST_PATH="${IMAGE_ROOT}"/trustedcore.img
KERNEL_NAME=teehm.img
KERNEL_PATH="${IMAGE_ROOT}"/"${KERNEL_NAME}"

IMG_PATH="${IMAGE_ROOT}"
KERNEL_ELF="${IMG_PATH}"/"${KERNEL_NAME}".elf
ELF_EXTRACT_SRC="${CURDIR}"/elf_extract.c
ELF_EXTRACT_BIN="${CURDIR}"/elf_extract

if [ -f "${ELF_EXTRACT_BIN}" ];then
	echo "Info: found elf_extract tool"
	rm "${ELF_EXTRACT_BIN}"
fi

set +o errexit; GCC_VERSION=$(expr `gcc -dumpversion | cut -f1 -d.` \>= 5); set -o errexit
if [ "${GCC_VERSION}" -eq 1 ];then
DATA_TIME=-Wdate-time
fi

GENERAL_OPTIONS="-Wall -Werror -Wformat=2 -fPIC -fstack-protector-all -Wextra -Wfloat-equal \
                 -Wshadow -fsigned-char -fno-strict-aliasing -fno-common -pipe -Wtrampolines"
LINK_OPTIONS="-pie -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wl,-Bsymbolic -Wl,--no-undefined -rdynamic"
if [ -f "${ELF_EXTRACT_SRC}" ];then
	gcc "${ELF_EXTRACT_SRC}" -o "${ELF_EXTRACT_BIN}" ${GENERAL_OPTIONS} ${DATA_TIME} -D${HM_ARCH} ${LINK_OPTIONS}
	if [ "$?" -ne 0 ];then
	echo "Error: build elf_extract tool fail"; exit -1
	fi
else
	echo "Error: Can not find elf_extract tool"; exit -1
fi

#Add new internal task here:
TASK_LIST=""
TASK_HIVCODEC_LIST=""

KERNEL_SYMTAB_OFFSET=$(ls -l "${KERNEL_PATH}"| awk '{print $5}')

"${ELF_EXTRACT_BIN}" "rtosck" "${KERNEL_ELF}" "${KERNEL_PATH}"

if [ "$?" -ne 0 ];then
    echo "Error: elf64_extract rtosck failed."; exit -1
fi

KERNEL_TOTAL_SIZE=$(ls -l "${KERNEL_PATH}"| awk '{print $5}')
KERNEL_SYMSTR_TOTAL_SIZE=$(expr "${KERNEL_TOTAL_SIZE}" - "${KERNEL_SYMTAB_OFFSET}")

KERNEL_SYMTAB_SIZE=$(readelf -S -W "${KERNEL_ELF}" 2>/dev/null | awk '{if ($2==".symtab") {print $6} else {if ($3==".symtab") {print $7}}}')
KERNEL_SYM_HEAD="${KERNEL_SYMTAB_OFFSET},${KERNEL_SYMTAB_SIZE},${KERNEL_SYMSTR_TOTAL_SIZE}"

GOT_SIZE=0
"${CURDIR}"/header.py  "${DST_PATH}" "${KERNEL_PATH}" "${KERNEL_TEXT_BASE}" "${GOT_SIZE}" "${KERNEL_SYM_HEAD}" "${COMPARE_IMAGE}" "${IMAGE_LOAD_ADDR}" "${KECC1PUB_PLAT}"
RET="$?"
if [ 0 -ne "${RET}" ];then
    echo "failed to do header.py ret is ${RET}"
	if [ -f "${DST_PATH}" ];then
	    rm "${DST_PATH}"
	fi
else
    echo "succeed to execute head.py"
fi

if [ x${VERSION_DDK} != "xy" ];then
	if [ -f "${ELF_EXTRACT_BIN}" ];then
		echo "Info: found elf64_extract tool"; rm "${ELF_EXTRACT_BIN}"
	fi
fi

RET="$?"
exit "${RET}"
