#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

config_host()
{
    cd ${HOST_OUT};configure_host
}

config_aarch64()
{
    cd ${OUT64};configure_aarch64
}

config_arm()
{
    cd ${OUT32};configure_arm
}

install_arm()
{
    cd ${OUT32};cmake --build . --target install_headers_32 -j${parallel_threads}
}

install_aarch64()
{
    cd ${OUT64};cmake --build . --target install_headers_64 -j${parallel_threads}
}

compile_host()
{
    cd ${HOST_OUT}
    cmake --build . --target release_host -j${parallel_threads}
    cmake -DCOMPONENT=bins_install -P cmake_install.cmake
}

compile_aarch64()
{
    cd ${OUT64}
    cmake --build . --target release_64 -j${parallel_threads}
    cmake --build . --target check_symbols -j${parallel_threads}
    cmake -DCOMPONENT=bins_install -P cmake_install.cmake
    cmake -DCOMPONENT=libs_install -P cmake_install.cmake
}

compile_arm()
{
    cd ${OUT32}
    cmake --build . --target release_32 -j${parallel_threads}
    cmake --build . --target check_symbols -j${parallel_threads}
    cmake -DCOMPONENT=bins_install -P cmake_install.cmake
    cmake -DCOMPONENT=libs_install -P cmake_install.cmake
}

configure_host()
{
    cmake \
        -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
        -DCMAKE_MODULE_PATH=${ABS_SOURCE_PATH}/cmake \
        -DCONFIG_FILE=${CONFIG_FILE} \
        -DTARGET_BOARD_PLATFORM=${TARGET_BOARD_PLATFORM} \
        -DOBB_PRODUCT_NAME=${OBB_PRODUCT_NAME} \
        -DBUILD_TOOL="host" \
        -DPREBUILD_PATH=${PREBUILD_PATH} \
        -DOUTPUTDIR=${STAGE_DIR} \
        -DBOOTFS_STAGE_DIR=${BOOTFS_STAGE_DIR} \
        -DBOOTFS_OUT=${BOOTFS_OUT} \
        -DIMAGE_ROOT=${IMAGE_ROOT} \
        -Dchip_type=${chip_type} \
        -Dproduct_type=${product_type} \
        -DTARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
        -DGCC_VERSION=${GCC_VERSION} \
        -DCFG_HISI_MINI_AP=${CFG_HISI_MINI_AP} \
        -DVERSION=`date +%d/%m/%Y-%H:%M:%S` \
        -DBUILD_TEST=${BUILD_TEST} \
        -DBUILD_TA_NAME=${BUILD_TA_NAME} \
        ${ABS_SOURCE_PATH}
}

configure_aarch64()
{
    if [ "$ARCH" = "aarch64" ]; then
        BUILD_KERNEL=y
    else
        BUILD_KERNEL=n
    fi
    cmake \
        -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
        -DARCH=aarch64 \
        -DCMAKE_MODULE_PATH=${ABS_SOURCE_PATH}/cmake \
        -DCMAKE_TOOLCHAIN_PATH=${ABS_SOURCE_PATH}/prebuild/toolchains \
        -DCMAKE_TOOLCHAIN_FILE=${ABS_SOURCE_PATH}/cmake/toolchains/${TOOLCHAIN_FILE_64} \
        -DCONFIG_FILE=${CONFIG_FILE} \
        -DTARGET_BOARD_PLATFORM=${TARGET_BOARD_PLATFORM} \
        -DOBB_PRODUCT_NAME=${OBB_PRODUCT_NAME} \
        -DBUILD_TOOL="clang" \
        -DPREBUILD_PATH=${PREBUILD_PATH} \
        -DTARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
        -DHMAPPS_COMMIT=${HMAPPS_COMMIT} \
        -DOUTPUTDIR=${OUTPUTDIR_64} \
        -DBOOTFS_STAGE_DIR=${BOOTFS_STAGE_DIR} \
        -DBOOTFS_OUT=${BOOTFS_OUT} \
        -DIMAGE_ROOT=${IMAGE_ROOT} \
        -Dchip_type=${chip_type} \
        -Dproduct_type=${product_type} \
        -DTARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
        -DHOST_BINS_DIR=${STAGE_DIR} \
        -DBUILD_KERNEL=${BUILD_KERNEL} \
        -DCFG_HISI_MINI_AP=${CFG_HISI_MINI_AP} \
        -DGET_XOM_FILE=${GET_XOM_FILE} \
        -DVERSION=`date +%d/%m/%Y-%H:%M:%S` \
        -DBUILD_TEST=${BUILD_TEST} \
        -DBUILD_TA_NAME=${BUILD_TA_NAME} \
        ${ABS_SOURCE_PATH}
}

configure_arm()
{
    if [ "$ARCH" = "arm" ]; then
        BUILD_KERNEL=y
    else
        BUILD_KERNEL=n
    fi
    cmake \
        -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
        -DARCH=arm \
        -DCMAKE_MODULE_PATH=${ABS_SOURCE_PATH}/cmake \
        -DCMAKE_TOOLCHAIN_PATH=${ABS_SOURCE_PATH}/prebuild/toolchains \
        -DCMAKE_TOOLCHAIN_FILE=${ABS_SOURCE_PATH}/cmake/toolchains/${TOOLCHAIN_FILE_32} \
        -DCONFIG_FILE=${CONFIG_FILE} \
        -DTARGET_BOARD_PLATFORM=${TARGET_BOARD_PLATFORM} \
        -DOBB_PRODUCT_NAME=${OBB_PRODUCT_NAME} \
        -DBUILD_TOOL="clang" \
        -DPREBUILD_PATH=${PREBUILD_PATH} \
        -DTARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
        -DHMAPPS_COMMIT=${HMAPPS_COMMIT} \
        -DOUTPUTDIR=${OUTPUTDIR_32} \
        -DBOOTFS_STAGE_DIR=${BOOTFS_STAGE_DIR} \
        -DBOOTFS_OUT=${BOOTFS_OUT} \
        -DIMAGE_ROOT=${IMAGE_ROOT} \
        -Dchip_type=${chip_type} \
        -Dproduct_type=${product_type} \
        -DTARGET_BUILD_VARIANT=${TARGET_BUILD_VARIANT} \
        -DHOST_BINS_DIR=${STAGE_DIR} \
        -DUSE_XOM32=${USE_XOM32} \
        -DBUILD_KERNEL=${BUILD_KERNEL} \
        -DCFG_HISI_MINI_AP=${CFG_HISI_MINI_AP} \
        -DGET_XOM_FILE=${GET_XOM_FILE} \
        -DVERSION=`date +%d/%m/%Y-%H:%M:%S` \
        -DBUILD_TEST=${BUILD_TEST} \
        -DBUILD_TA_NAME=${BUILD_TA_NAME} \
        ${ABS_SOURCE_PATH}
}
