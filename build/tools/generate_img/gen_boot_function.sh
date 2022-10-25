#!/bin/bash
# function belong to gen_boot_image.
# Copyright Huawei Technologies Co., Ltd. 2010-2022. All rights reserved.
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

fail() {
    echo "(failed)" > /dev/stderr
    [ -n "${TEMP_DIR}" ] && rm -rf "${TEMP_DIR}"
    exit 1
}

do_others() {
    # Strip CPIO metadata if possible.
    if [ "${DDK_FLAG}" != "true" ]; then
        CPIO_STRIP="$BUILD_TOOLS"/generate_img/cpio-strip/cpio-strip
    else
        CPIO_STRIP="$TOPDIR"/prebuild/hm-teeos-release/tools/cpio-strip
    fi
    "$CPIO_STRIP" "${TEMP_DIR}"/archive.cpio
        UNZIP_SIZE=$(ls -l "${TEMP_DIR}"/archive.cpio | awk '{print $5}')
    if [ "${CONFIG_NO_ZIP_IMAGE}" == "true" ]; then
        cp "${TEMP_DIR}"/archive.cpio "${TEMP_DIR}"/archive.cpio.gz
    else
        gzip -n -c "${TEMP_DIR}"/archive.cpio > "${TEMP_DIR}"/archive.cpio.gz
        echo "before zipped size is ${UNZIP_SIZE}"
    fi

    if [ "$?" -ne 0 ]; then
        fail
    fi

    popd &>/dev/null

    pushd "${TEMP_DIR}" >/dev/null
    cp "${TEMP_DIR}"/archive.cpio.gz "${TEMP_DIR}"/archive.data

    if [ "$HM_ARCH" == "aarch64" ] ; then
        emul="aarch64elf"
    else
        emul="armelf"
    fi
    ${LD} -T "${SCRIPT_DIR}/archive.bin.lds" \
            --oformat "${FORMAT}" -r -b binary -m ${emul} archive.data \
            -o "${TEMP_DIR}/archive.o" || fail
    popd >/dev/null

    LINKER_DIR="$OUTPUTDIR"/arm/package
    mkdir -p "$LINKER_DIR"
    ARCHIVE_FLAGS="-DUNZIP_SIZE=${UNZIP_SIZE}"
    ${CC} ${SDK_CPPFLAGS} ${ARCHIVE_FLAGS} -P -E \
            -o "${LINKER_DIR}/linker.lds_pp" \
            -x c "${SCRIPT_DIR}/linker.lds"

    if [ "${DDK_FLAG}" != "true" ]; then
        CC_PLATFORM_ES=""
        if [ "${chip_type}" == "es" ]; then
            CC_PLATFORM_ES="_es"
        fi
        if [ "${CONFIG_NO_PLATCFG_EMBEDDED}" != "true" ]; then
            ${CC} ${SDK_CPPFLAGS} -I"${PLAT_CFG_DIR}"/ \
                -I"${PLAT_COMMON_DIR}"/include/ \
                -I${TOPDIR}/prebuild/hm-teeos-release/headers/kernel/include/arch/arm/uapi/ \
                -I${TOPDIR}/prebuild/hm-teeos-local-release/headers/kernel/include/arch/arm/uapi/ \
                -I${OUTPUTDIR}/prebuild/hm-teeos-release/headers/kernel/include/arch/arm/uapi/ \
                -I${OUTPUTDIR}/prebuild/hm-teeos-local-release/headers/kernel/include/arch/arm/uapi/ \
                -Wall -Wextra -Werror -Wformat=2 -c \
                -o "${LINKER_DIR}/plat_cfg.o" \
                ""${PLAT_CFG_DIR}"/plat_cfg.c"
            LINK_PLAT_CFG="${LINKER_DIR}/plat_cfg.o"
        fi
    fi

    ${LD} -T "${LINKER_DIR}/linker.lds_pp" \
    -z relro -z now -z notext -pie --apply-dynamic-relocs\
    --oformat "${FORMAT}" \
    "${ELFLOADER_DIR}/elfloader.o" "${TEMP_DIR}/archive.o" \
    "${LINK_PLAT_CFG}" \
    "${KERNEL_OUTDIR}"/libklibc.a "${KERNEL_OUTDIR}"/libhardware.a "${KERNEL_OUTDIR}"/libuart.a \
    -o "${OUTPUT_FILE}" \
        || fail

    [ -n "${TEMP_DIR}" ] && rm -rf "${TEMP_DIR}"

}

