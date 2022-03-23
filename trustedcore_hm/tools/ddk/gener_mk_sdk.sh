#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

OUTPUT_DIR=$(pwd)

FILE_NAME=trustedcore_ddk_v0.1
TMP_DIR=$(mktemp -d)
WORK_DIR="$TMP_DIR"/"$FILE_NAME"

## step 1: file mkdir prepare
mkdir -p "$WORK_DIR"/tools/ "$WORK_DIR"/prebuild/ "$WORK_DIR"/platform/
mkdir -p "$WORK_DIR"/libs/ "$WORK_DIR"/drivers/ "$WORK_DIR"/mk/

## step 2: tools set up
mkdir -p "$WORK_DIR"/tools/cpio-strip/ "$WORK_DIR"/tools/xom/
cp -r "$OUTPUT_DIR"/tools/hmfilemgr "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/cpio-strip/cpio-strip "$WORK_DIR"/tools/cpio-strip/
cp "$OUTPUT_DIR"/tools/smart-strip.sh "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/ddk/packimg_ddk.sh "$WORK_DIR"/tools/packimg.sh
cp "$OUTPUT_DIR"/tools/linker.lds "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/header_mtk.py "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/gen_boot_image.sh "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/gen_boot_function.sh "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/elf_extract "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/check-syms.sh "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/archive.bin.lds "$WORK_DIR"/tools/
cp "$OUTPUT_DIR"/tools/xom/xom "$WORK_DIR"/tools/xom

## step 3: prebuild set up
mkdir -p "$WORK_DIR"/prebuild/toolchains
source ./tools/ddk/generate_sdk.sh
source ./tools/ddk/gener_tee_sdk.sh

## step 4: platform set up
mkdir -p "$WORK_DIR"/platform/mtk/ "$WORK_DIR"/platform/common/ "$WORK_DIR"/platform/mtk/phone/mt6885
mkdir -p "$WORK_DIR"/platform/mtk/phone/mt6885/timer "$WORK_DIR"/platform/mtk/phone/mt6885/platdrv
mkdir -p "$WORK_DIR"/platform/mtk/phone/common/modules
cp "$OUTPUT_DIR"/platform/common/tee_common.mk "$WORK_DIR"/platform/common/
cp -r "$OUTPUT_DIR"/platform/mtk/phone/mt6885/timer/mk "$WORK_DIR"/platform/mtk/phone/mt6885/timer/
cp -r "$OUTPUT_DIR"/platform/mtk/phone/mt6885/platdrv/mk "$WORK_DIR"/platform/mtk/phone/mt6885/platdrv/
cp -r "$OUTPUT_DIR"/platform/mtk/phone/mt6885/modules "$WORK_DIR"/platform/mtk/phone/mt6885/
cp "$OUTPUT_DIR"/platform/mtk/phone/mt6885/product_config.mk "$WORK_DIR"/platform/mtk/phone/mt6885/
cp "$OUTPUT_DIR"/platform/mtk/phone/mt6885/chip.mk "$WORK_DIR"/platform/mtk/phone/mt6885/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/modules/platdrv_common.mk "$WORK_DIR"/platform/mtk/phone/common/modules/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/modules/modules.mk "$WORK_DIR"/platform/mtk/phone/common/modules/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/modules/keymaster.mk "$WORK_DIR"/platform/mtk/phone/common/modules/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/modules/gatekeeper.mk "$WORK_DIR"/platform/mtk/phone/common/modules/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/modules/*.mk "$WORK_DIR"/platform/mtk/phone/common/modules/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/product_config.mk "$WORK_DIR"/platform/mtk/phone/common/
cp "$OUTPUT_DIR"/platform/mtk/phone/common/chip.mk "$WORK_DIR"/platform/mtk/phone/common/
cp "$OUTPUT_DIR"/platform/mtk/platform.mk "$WORK_DIR"/platform/mtk/
cp "$OUTPUT_DIR"/platform/mtk/README "$WORK_DIR"/platform/mtk/

## step 5: mk set up
mkdir -p "$WORK_DIR"/mk
cp "$OUTPUT_DIR"/mk/bootfs.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/tools/ddk/ddk_lib.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/tools/ddk/ddk_drv.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/llvm-apps-cfi.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/llvm-apps-xom.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/rule.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/ta_link.ld "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/ta_link_64.ld "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/ta_link_new.ld "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/toolchain.mk "$WORK_DIR"/mk/
cp "$OUTPUT_DIR"/mk/var.mk "$WORK_DIR"/mk/

## step 6: libs set up
mkdir -p "$WORK_DIR"/libs/mtk-platdrv/platform/mtk
cp -rf "$OUTPUT_DIR"/libs/libplatdrv/platform/mtk/mk "$WORK_DIR"/libs/mtk-platdrv/platform/mtk/

## step 7: drivers set up
mkdir -p "$WORK_DIR"/drivers/platdrv
cp "$OUTPUT_DIR"/tools/ddk/platdrv/Makefile_ddk "$WORK_DIR"/drivers/platdrv/Makefile_ddk
cp "$OUTPUT_DIR"/drivers/platdrv/linker64.ld "$WORK_DIR"/drivers/platdrv/
cp "$OUTPUT_DIR"/drivers/platdrv/linker.ld "$WORK_DIR"/drivers/platdrv/
cp "$OUTPUT_DIR"/drivers/platdrv/linker.xom.ld "$WORK_DIR"/drivers/platdrv/
cp "$OUTPUT_DIR"/drivers/platdrv/export.txt "$WORK_DIR"/drivers/platdrv/

## step 8: cp others
cp "$OUTPUT_DIR"/README.md "$WORK_DIR"/
cp "$OUTPUT_DIR"/tools/ddk/Makefile_ddk "$WORK_DIR"/Makefile
cp "$OUTPUT_DIR"/config.mk "$WORK_DIR"/
cp "$OUTPUT_DIR"/tools/ddk/ddk_config.mk "$WORK_DIR"/ddk_config.mk

## step 9: release set up
mkdir -p "$WORK_DIR"/prebuild/hm-apps-release "$WORK_DIR"/prebuild/hm-teeos-release
cp -r "$WORK_DIR_APP"/* "$WORK_DIR"/prebuild/hm-apps-release/
cp -r "$WORK_DIR_TEE"/* "$WORK_DIR"/prebuild/hm-teeos-release/

## step 10: tar release
tar -zcf "$OUTPUT_DIR"/"$FILE_NAME".tar.gz -C "$TMP_DIR" "$FILE_NAME"

echo "@@@@@@@@@@@@@@@@@@@@@@   $OUTPUT_DIR    @@@@@@@@@@@@@@@@@@@@@@@@@@@"
