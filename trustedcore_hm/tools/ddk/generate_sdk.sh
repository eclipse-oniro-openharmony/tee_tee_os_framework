#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

OUTPUT_DIR=$(pwd)

FILE_NAME_APP=hm-apps-release-mtk-v0.1
TMP_DIR_APP=$(mktemp -d)
WORK_DIR_APP="$TMP_DIR_APP"/"$FILE_NAME_APP"
AUTOCONF_MACRO_FILE="$HM_TEEOS_DIR"/tools/automacro.h

function release_apps_headers() {
for  line  in  $(cat "$OUTPUT_DIR"/tools/$1); do
    src_file=$(echo $line | awk -F ":" '{print $1}')
    dst_file=$(echo $line | awk -F ":" '{print $2}')
    if [ "$dst_file" =  "" ];then
        dst_dir=$(dirname $src_file)
    else
        dst_dir=$(dirname $dst_file)
    fi
    if [ ! -d "$dst_dir" ];then
        mkdir -p "$WORK_DIR_APP"/headers/"$dst_dir"
    fi
    cp -rf "$OUTPUT_DIR"/$src_file "$WORK_DIR_APP"/headers/"$dst_dir"/
done
}

function release_teeos_libs() {
for  filename  in  $(cat "$OUTPUT_DIR"/tools/$1); do
    file_32="$OUTPUT_DIR"/output/arm/libs/"$filename"
    file_64="$OUTPUT_DIR"/output/aarch64/libs/"$filename"
    if [ -f "$file_32" ]; then
            cp -rf "$file_32" "$WORK_DIR_APP"/arm/libs/
    fi
    if [ -f "$file_64" ]; then
            cp -rf "$file_64" "$WORK_DIR_APP"/aarch64/libs/
    fi
done
}

## step 1: prepare folders...
mkdir -p "$WORK_DIR_APP"/arm/apps "$WORK_DIR_APP"/arm/drivers "$WORK_DIR_APP"/arm/libs  "$WORK_DIR_APP"/headers
mkdir -p "$WORK_DIR_APP"/aarch64/apps "$WORK_DIR_APP"/aarch64/drivers "$WORK_DIR_APP"/aarch64/libs
mkdir -p "$WORK_DIR_APP"/arm/obj/arm-mtk/platdrv/src "$WORK_DIR_APP"/arm/package "$WORK_DIR_APP"/aarch64/apps

## step 2: cp headers && clean no use include
release_apps_headers ddk/release_apps_header.txt
grep -rl 'sre_typedef.h' "$WORK_DIR_APP"/headers/mtk/drv_module.h | xargs sed -i 's/#include "sre_typedef.h".*//g'

## step 3: cp libs
find "$OUTPUT_DIR"/output/arm/libs/ -type l |xargs rm -rf
find "$OUTPUT_DIR"/output/aarch64/libs/ -type l |xargs rm -rf
release_teeos_libs ddk/release_lib.txt

## step 4: cp drivers
find "$OUTPUT_DIR"/output/arm/drivers/ -name platdrv.elf|xargs rm -rf
cp -rf "$OUTPUT_DIR"/output/arm/drivers/* "$WORK_DIR_APP"/arm/drivers
cp -rf "$OUTPUT_DIR"/output/aarch64/drivers/* "$WORK_DIR_APP"/aarch64/drivers

## step 5: cp apps
cp -rf "$OUTPUT_DIR"/output/arm/apps/* "$WORK_DIR_APP"/arm/apps
cp -rf "$OUTPUT_DIR"/output/aarch64/apps/* "$WORK_DIR_APP"/aarch64/apps

## step 6: cp libtee_shared.so
cp "$OUTPUT_DIR"/output/arm/obj/arm/libtee_shared/libtee_shared_a32.so "$WORK_DIR_APP"/arm
cp "$OUTPUT_DIR"/output/aarch64/obj/aarch64/libtee_shared/libtee_shared.so "$WORK_DIR_APP"/aarch64
cp "$OUTPUT_DIR"/output/arm/obj/arm/libvendor_shared/libvendor_shared_a32.so "$WORK_DIR_APP"/arm
cp "$OUTPUT_DIR"/output/aarch64/obj/aarch64/libvendor_shared/libvendor_shared.so "$WORK_DIR_APP"/aarch64
cp "$OUTPUT_DIR"/output/arm/obj/arm/libtui_internal_shared/libtui_internal_shared_a32.so "$WORK_DIR_APP"/arm
cp "$OUTPUT_DIR"/output/aarch64/obj/aarch64/libtui_internal_shared/libtui_internal_shared.so "$WORK_DIR_APP"/aarch64
cp "$OUTPUT_DIR"/output/arm/obj/arm/libgm_shared/libgm_shared_a32.so "$WORK_DIR_APP"/arm
cp "$OUTPUT_DIR"/output/aarch64/obj/aarch64/libgm_shared/libgm_shared.so "$WORK_DIR_APP"/aarch64

## step 7: cp platdrv/src *.o
find "$OUTPUT_DIR"/output/arm/obj/arm/platdrv -name *.d|xargs rm -rf
cp "$OUTPUT_DIR"/output/arm/obj/arm/platdrv/src/* "$WORK_DIR_APP"/arm/obj/arm-mtk/platdrv/src
cp -r "$OUTPUT_DIR"/output/arm/obj/arm/platdrv/platform "$WORK_DIR_APP"/arm/obj/arm-mtk/platdrv
#cp -r "$OUTPUT_DIR"/output/arm/obj/arm/platdrv/home "$WORK_DIR_APP"/arm/obj/arm-mtk/platdrv
#DRV_HASH_INIT=$(find output/ -name drv_hash_init.o)
#echo "@@@@@  $DRV_HASH_INIT  @@@@@"
#cp "$OUTPUT_DIR"/"$DRV_HASH_INIT" "$WORK_DIR_APP"/arm/obj/arm-mtk/platdrv/src

## step 8: cp plat_cfg.o
cp "$OUTPUT_DIR"/output/arm/package/plat_cfg.o "$WORK_DIR_APP"/arm/package

## step 9: tar release
tar -zcf "$OUTPUT_DIR"/"$FILE_NAME_APP".tar.gz -C "$TMP_DIR_APP" "$FILE_NAME_APP"

echo "@@@@@@@@@@@@@@@@@@@@@@   $OUTPUT_DIR    @@@@@@@@@@@@@@@@@@@@@@@@@@@"
