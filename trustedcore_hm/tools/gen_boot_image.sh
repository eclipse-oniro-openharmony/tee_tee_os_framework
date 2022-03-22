#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.]
set -e
source ./tools/gen_boot_function.sh

V=3

if [ 0"${V}" -ge 3 ]; then
    set -x
fi

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <kernel elf> <user elf> <output file>"
    exit 1
fi

KERNEL_IMAGE="$1" ; shift 1
sep=""
while [ "$#" -ne 1 ]; do
	USER_IMAGES="$USER_IMAGES$sep$1" ; shift 1
	sep=" "
done

OUTPUT_FILE="$1" ; shift 1
if [ "$HM_ARCH" == "aarch64" ] ; then
	ENTRY_ADDR=0x48000000 ; FORMAT=elf64-littleaarch64
else
	ENTRY_ADDR=0x48000000 ; FORMAT=elf32-littlearm
    fi

if [ ! -e "${KERNEL_IMAGE}" ]; then
	echo "File '${KERNEL_IMAGE}' does not exist."; exit 1
fi

for USER_IMAGE in $USER_IMAGES; do
	if [ ! -e "${USER_IMAGE}" ]; then
		echo "File '${USER_IMAGE}' does not exist."; exit 1
	fi
done

# Get the script's location.
SCRIPT_PATH=$(readlink -f ${BASH_SOURCE[0]})
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")

# Create working directory.
# Warning: mktemp functions differently on Linux and OSX.
TEMP_DIR=$(mktemp -d -t HMXXXX)

if [ "${PLAT}" != "virt" ]; then
	CPIO_EXE=$(which cpio)
else
	CPIO_EXE=cpio
fi

# Generate an archive of the userspace and kernel images.
pad8_kernel_img_name=$(pad8_name "kernel.elf")
mkdir -p "${TEMP_DIR}/cpio"
cp -f "${KERNEL_IMAGE}" "${TEMP_DIR}"/cpio/"${pad8_kernel_img_name}"

pad8_user_images=""
sep=""
for USER_IMAGE in ${USER_IMAGES}; do
	tmp_name=$(pad8_name $(basename "${USER_IMAGE}"))
	cp -f "${USER_IMAGE}" "${TEMP_DIR}"/cpio/"${tmp_name}"
	pad8_user_images="${pad8_user_images}""${sep}""${tmp_name}"
	sep=" "
done

${STRIP} -p --strip-debug "${TEMP_DIR}"/cpio/*

pushd "${TEMP_DIR}/cpio" &>/dev/null
(
	printf "${pad8_kernel_img_name}\n"
	for USER_IMAGE in $pad8_user_images; do
		printf "$(basename ${USER_IMAGE})\n"
		printf "$(basename ${USER_IMAGE})\n" 1>&2
	done
) | "${CPIO_EXE}" --quiet -o -H newc > "${TEMP_DIR}"/archive.cpio

if [ $? -ne 0 ]; then
    fail
fi

do_others

exit 0
