#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

OUTPUT_DIR=$(pwd)

FILE_NAME_TEE=hm-teeos-release-mtk-v0.1
TMP_DIR_TEE=$(mktemp -d)
WORK_DIR_TEE="$TMP_DIR_TEE"/"$FILE_NAME_TEE"
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
        mkdir -p "$WORK_DIR_TEE"/headers/"$dst_dir"
    fi
    cp -rf "$OUTPUT_DIR"/$src_file "$WORK_DIR_TEE"/headers/"$dst_dir"/
done
}

function release_teeos_libs() {
for  filename  in  $(cat "$OUTPUT_DIR"/tools/$1); do
    file_32="$OUTPUT_DIR"/prebuild/hm-teeos-local-release/libs/arm/"$filename"
    file_64="$OUTPUT_DIR"/prebuild/hm-teeos-local-release/libs/aarch64/"$filename"
    if [ -f "$file_32" ]; then
            cp -rf "$file_32" "$WORK_DIR_TEE"/libs/arm/
    fi
    if [ -f "$file_64" ]; then
            cp -rf "$file_64" "$WORK_DIR_TEE"/libs/aarch64/
    fi
done
}

## step 1: prepare folders...
mkdir -p "$WORK_DIR_TEE" "$WORK_DIR_TEE"/libs/arm "$WORK_DIR_TEE"/libs/aarch64 "$WORK_DIR_TEE"/tools
mkdir -p "$WORK_DIR_TEE"/headers/libc "$WORK_DIR_TEE"/headers/libc_32 "$WORK_DIR_TEE"/headers/sdk/teeapi/common 

## step 2: cp tools apps kernel
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/tools "$WORK_DIR_TEE"/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/apps "$WORK_DIR_TEE"/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/kernel "$WORK_DIR_TEE"/
rm -rf "$WORK_DIR_TEE"/tools/scrambled_syms
rm -rf "$WORK_DIR_TEE"/apps/rpmb_a32
rm -rf "$WORK_DIR_TEE"/apps/ssa_a32
## step 3: cp libs
release_teeos_libs ddk/release_teeos_lib.txt

## step 4: cp headers
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/headers/libc/* "$WORK_DIR_TEE"/headers/libc/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/headers/libc_32/* "$WORK_DIR_TEE"/headers/libc_32/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/headers/sdk/teeapi/common/tee_log.h "$WORK_DIR_TEE"/headers/sdk/teeapi/common/
grep -rl 'tee_defines.h' "$WORK_DIR_TEE"/headers/sdk/teeapi/common/tee_log.h | xargs sed -i 's/#include "tee_defines.h".*//g'
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/headers/autoconf.h "$WORK_DIR_TEE"/headers/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/headers/.config "$WORK_DIR_TEE"/headers/

## step 5: cp tools
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/tools/ramfsmkimg "$WORK_DIR_TEE"/tools/
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/tools/ramfsdump "$WORK_DIR_TEE"/tools/
cp -r "$OUTPUT_DIR"/tools/cpio-strip/cpio-strip "$WORK_DIR_TEE"/tools
cp -r "$OUTPUT_DIR"/prebuild/hm-teeos-local-release/tools/scramb_syms_host "$WORK_DIR_TEE"/tools

## step 5: mv kirin mtk
#mv "$WORK_DIR_TEE"/headers/kernel/kirin "$WORK_DIR_TEE"/headers/kernel/mtk
#mv "$WORK_DIR_TEE"/apps/kirin "$WORK_DIR_TEE"/apps/mtk
#mv "$WORK_DIR_TEE"/kernel/aarch64-kirin "$WORK_DIR_TEE"/kernel/aarch64-mtk


## step 9: tar release
tar -zcf "$OUTPUT_DIR"/"$FILE_NAME_TEE".tar.gz -C "$TMP_DIR_TEE" "$FILE_NAME_TEE"

echo "@@@@@@@@@@@@@@@@@@@@@@   $OUTPUT_DIR    @@@@@@@@@@@@@@@@@@@@@@@@@@@"
