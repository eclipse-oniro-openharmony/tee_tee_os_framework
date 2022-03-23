#! /bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e
COMPARE_IMAGE="$3"

KERNEL_TEXT_BASE="$1"; echo "kernel text base=${KERNEL_TEXT_BASE}"

PLATFORM_CHOOSE="$2"; echo "platform is ${PLATFORM_CHOOSE}"

CHIP_CHOOSE="$4"; echo "chip is ${CHIP_CHOOSE}"

TEEOS_IMG_ENCRYPT="$5"; echo "TEE IMG encrypt is ${TEEOS_IMG_ENCRYPT}"

if [ "${TEEOS_IMG_ENCRYPT}" ]; then
  echo "TEE IMG encrypt is ${TEEOS_IMG_ENCRYPT}"
else
	echo "Error:there is no input TEEOS_IMG_ENCRYPT Feature"; exit -1
fi

TEEOS_LOG_ENCODE="$6"; echo "TEEOS_LOG_ENCODE is ${TEEOS_LOG_ENCODE}"

IMAGE_LOAD_ADDR="$7"; echo "IMAGE_LOAD_ADDR is ${IMAGE_LOAD_ADDR}"

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
ELF_EXTRACT_BIN="${CURDIR}"/elf_extract

GENERAL_OPTIONS="-Wall -Werror -fPIC -fstack-protector-all -Wextra -Wfloat-equal \
                 -Wshadow -fsigned-char -fno-strict-aliasing -fno-common -pipe"

#Add new internal task here:
TASK_LIST=""
TASK_HIVCODEC_LIST=""

echo -e "task list: ${TASK_LIST} \n 1. repack rtosck.img and place their symbol tables to the file tail"

KERNEL_SYMTAB_OFFSET=$(ls -l "${KERNEL_PATH}"| awk '{print $5}')

"${ELF_EXTRACT_BIN}" "rtosck" "${KERNEL_ELF}" "${KERNEL_PATH}"

if [ "$?" -ne 0 ];then
    echo "Error: elf64_extract rtosck failed."; exit -1
fi

KERNEL_TOTAL_SIZE=$(ls -l "${KERNEL_PATH}"| awk '{print $5}')
KERNEL_SYMSTR_TOTAL_SIZE=$(expr "${KERNEL_TOTAL_SIZE}" - "${KERNEL_SYMTAB_OFFSET}")

echo "2. generator symbol table header for rtosck.img"
KERNEL_SYMTAB_SIZE=$(readelf -S -W "${KERNEL_ELF}" 2>/dev/null | awk '{if ($2==".symtab") {print $6} else {if ($3==".symtab") {print $7}}}')
KERNEL_SYM_HEAD="${KERNEL_SYMTAB_OFFSET},${KERNEL_SYMTAB_SIZE},${KERNEL_SYMSTR_TOTAL_SIZE}"

if [ "${TEEOS_IMG_ENCRYPT}" == true ]; then
	if [ "${CHIP_CHOOSE}" == "WITH_CHIP_MT6853" ];then
		KRSAPUB_PLAT=krsapub_mt6853.pem
		MTK_FLAG=1
	fi
    if [ "${CHIP_CHOOSE}" == "WITH_CHIP_MT6885" ];then
		KRSAPUB_PLAT=krsapub_mt6885.pem
		MTK_FLAG=1
	fi
	if [ "${CHIP_CHOOSE}" == "WITH_CHIP_MT6765" ] || [ "${CHIP_CHOOSE}" == "WITH_CHIP_MT6761" ];then
		KRSAPUB_PLAT=krsapub_mt676x.pem
		MTK_FLAG=1
	fi
fi

echo "TEEOS_IMG_ENCRYPT feature is ${TEEOS_IMG_ENCRYPT}, platform is ${CHIP_CHOOSE}"
GOT_SIZE=0
if [ "${MTK_FLAG}" ];then
  "${CURDIR}"/header_mtk.py "${DST_PATH}" "${KERNEL_PATH}" "${KERNEL_TEXT_BASE}" "${GOT_SIZE}" "${KERNEL_SYM_HEAD}" "${COMPARE_IMAGE}" "${IMAGE_LOAD_ADDR}" "${KRSAPUB_PLAT}"
elif [ "${KPENG_FLAG}" ];then
  "${CURDIR}"/header_kunpeng.py  "${DST_PATH}" "${KERNEL_PATH}" "${KERNEL_TEXT_BASE}" "${GOT_SIZE}" "${KERNEL_SYM_HEAD}" "${COMPARE_IMAGE}" "${IMAGE_LOAD_ADDR}" "${KRSAPUB_PLAT}"
elif [ "${CHIP_CHOOSE}" == "WITH_CHIP_HI5651T" ];then
  "${CURDIR}"/header_router.py "${DST_PATH}" "${KERNEL_PATH}" "${KERNEL_TEXT_BASE}" "${GOT_SIZE}" "${KERNEL_SYM_HEAD}" "${COMPARE_IMAGE}" "${IMAGE_LOAD_ADDR}" "${KRSAPUB_PLAT}"
else
  "${CURDIR}"/header.py  "${DST_PATH}" "${KERNEL_PATH}" "${KERNEL_TEXT_BASE}" "${GOT_SIZE}" "${KERNEL_SYM_HEAD}" "${COMPARE_IMAGE}" "${IMAGE_LOAD_ADDR}" "${KECC1PUB_PLAT}"
fi
RET="$?"
if [ 0 -ne "${RET}" ];then
    echo "failed to do header.py ret is ${RET}"
	if [ -f "${DST_PATH}" ];then
	    rm "${DST_PATH}"
	fi
else
    echo "succeed to execute head.py"
fi

#if [ -f "${ELF_EXTRACT_BIN}" ];then
#	echo "Info: found elf64_extract tool"; rm "${ELF_EXTRACT_BIN}"
#fi

RET="$?"
exit "${RET}"
