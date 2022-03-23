#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e
source ./gen_boot_function.sh
if [ 0"${V}" -ge 3 ]; then
    set -x
fi

if [ $# -lt 3 ]; then
   echo "Usage: $0 <kernel elf> <user elf> <output file>" && exit 1
fi

KERNEL_IMAGE="$1" && shift 1

sep=""
while [ $# -ne 1 ]; do
	USER_IMAGES="$USER_IMAGES$sep$1" && shift 1
	sep=" "
done
OUTPUT_FILE="$1" && shift 1

FORMAT=elf64-littleaarch64
ENTRY_ADDR=0x48000000
if [ "$HM_ARCH" != "aarch64" ];then
	FORMAT=elf32-littlearm
fi;;

check_files "${KERNEL_IMAGE}"

for USER_IMAGE in "$USER_IMAGES"; do
	check_files "${USER_IMAGE}"
done

SCRIPT_PATH=$(readlink -f ${BASH_SOURCE[0]})

SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"

TEMP_DIR=$(mktemp -d -t HMXXXX)

CPIO_EXE=$(which cpio)

if [ ! test -x "${CPIO_EXE}" ]; then
	echo "Not found cpio: ${CPIO_EXE}" >&2 ; fail
fi

pad8_kernel_img_name=$(pad8_name "kernel.elf")
mkdir -p "${TEMP_DIR}/cpio" && cp -f "${KERNEL_IMAGE}" "${TEMP_DIR}"/cpio/"${pad8_kernel_img_name}"

pad8_user_images=""
sep=""
for USER_IMAGE in "${USER_IMAGES}"; do
	tmp_name=$(pad8_name $(basename "${USER_IMAGE}"))
	cp -f "${USER_IMAGE}" "${TEMP_DIR}"/cpio/"${tmp_name}"
	pad8_user_images="${pad8_user_images}""${sep}""${tmp_name}"
	sep=" "
done

${STRIP} -p --strip-debug "${TEMP_DIR}"/cpio/*

pushd "${TEMP_DIR}/cpio" &>/dev/null
(
	printf "${pad8_kernel_img_name}\n"
	for USER_IMAGE in "$pad8_user_images"; do
		printf "$(basename ${USER_IMAGE})\n" 1>&2
	done
) | "${CPIO_EXE}" --quiet -o -H newc > "${TEMP_DIR}"/archive.cpio

HM_APPS_CPIO_STRIP := $(PWD)/../hm-apps/trustedcore_hm/tools/cpio-strip
CPIO_STRIP="${HM_APPS_CPIO_STRIP}"/cpio-strip
"${CPIO_STRIP}" "${TEMP_DIR}"/archive.cpio

gzip -c "${TEMP_DIR}"/archive.cpio > "${TEMP_DIR}"/archive.cpio.gz

popd &>/dev/null

pushd "${TEMP_DIR}" >/dev/null
if [ "${PLAT}" == "kirin" ]; then
	cp "${TEMP_DIR}"/archive.cpio.gz "${TEMP_DIR}"/archive.data
else
	cp "${TEMP_DIR}"/archive.cpio "${TEMP_DIR}"/archive.data
fi

${LD} -T "${SCRIPT_DIR}/archive.bin.lds" --oformat "${FORMAT}" -r -b binary archive.data -o "${TEMP_DIR}/archive.o" || fail
popd >/dev/null

${CC} "${CPPFLAGS}" -P -E -o "${SCRIPT_DIR}/linker.lds_pp" -x c "${SCRIPT_DIR}/linker.lds" -Wall -Werror -Wextra


if [ "${PLAT}" == "kirin" ]; then
	${LD} -T "${SCRIPT_DIR}/linker.lds_pp" --oformat "${FORMAT}" "${SCRIPT_DIR}/elfloader.o" "${TEMP_DIR}/archive.o" "${SCRIPT_DIR}/../../../../../build/kernel/libhardware.a" "${SCRIPT_DIR}/../../../../../build/kernel/klibc/klibc.a" -o "${OUTPUT_FILE}" || fail
else
	${LD} -T "${SCRIPT_DIR}/linker.lds_pp" --oformat "${FORMAT}" "${SCRIPT_DIR}/elfloader.o" "${TEMP_DIR}/archive.o" "${SCRIPT_DIR}/../../../../../build/kernel/libhardware.a" "${SCRIPT_DIR}/../../../../../build/kernel/klibc/klibc.a" -Ttext="${ENTRY_ADDR}" -o "${OUTPUT_FILE}" || fail
fi

[ -n "${TEMP_DIR}" ] && rm -rf "${TEMP_DIR}"
exit 0
