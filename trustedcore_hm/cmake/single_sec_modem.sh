#!/bin/bash
# laguna single sec modem configure&compile
set -e

configure_modem()
{
    cmake \
        -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
        -DARCH=arm \
        -DCMAKE_MODULE_PATH=${ABS_SOURCE_PATH}/cmake \
        -DCMAKE_TOOLCHAIN_PATH=${TOOLCHAIN_ROOT} \
        -DCMAKE_TOOLCHAIN_BASEVER=${LLVM_TOOLCHAIN_BASEVER} \
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
        -DVERSION=`date +%d/%m/%Y-%H:%M:%S` \
        -DBUILD_SINGLE_MOD=${BUILD_SINGLE_MOD} \
        ${ABS_SOURCE_PATH}
}

compile_single_modem()
{
    cd ${OUT_MODEM}

    ###############
    # compile xom #
    ###############
    if [ "${USE_XOM32}" == "y" ]; then
        configure_host
        echo "compile xom32"
        cmake --build . --target xom -j${parallel_threads}
        rm -rf `ls | grep -v tools`
    fi

    #############
    # sec modem #
    #############
    configure_modem
    echo "compile sec modem"
    cmake --build . --target single_sec_modem -j${parallel_threads}

    ##################
    # running XOM32. #
    ##################
    OBJCOPY=${TOOLCHAIN_ROOT}/clang+llvm/bin/llvm-objcopy
    SEC_MODEM_PATH=libs/hisi-platdrv/platform/kirin/sec_modem
    cp ${OUT_MODEM}/${SEC_MODEM_PATH}/libsingle_sec_modem.so ${OUT_MODEM}/sec_modem.so
    if [ "${USE_XOM32}" == "y" ]; then
        echo "run xom32"
        ${OUT_MODEM}/tools/xom/xom ${OUT_MODEM}/sec_modem.so
        ${OBJCOPY} ${OUT_MODEM}/sec_modem.so --remove-section ".xomloc"
    else
        ${OBJCOPY} ${OUT_MODEM}/sec_modem.so
    fi

    #############
    # signtools #
    #############
    SIGNTOOLS_PATH=${ABS_SOURCE_PATH}/../../itrustee_sdk/build/signtools
    if [ "${RELEASE_SIGN}" == "true" ]; then
        INI_FILE_PATH=${SIGNTOOLS_PATH}/config_cbg_release.ini
    else
        INI_FILE_PATH=${SIGNTOOLS_PATH}/config_cbg_debug_only_sign.ini
    fi
    MODEM_INPUT_PATH=${OUT_MODEM}/input
    MODEM_OUTPUT_PATH=${OUT_MODEM}/output
    export NATIVE_CA_SIGN_JAR_PATH=${ABS_SOURCE_PATH}/../../../../../tools/signcenter/NativeCASign.jar
    mkdir -p ${MODEM_INPUT_PATH}
    mkdir -p ${MODEM_OUTPUT_PATH}
    cp ${OUT_MODEM}/sec_modem.so $MODEM_INPUT_PATH/libcombine.so
    cp ${ABS_SOURCE_PATH}/${SEC_MODEM_PATH}/manifest.txt ${MODEM_INPUT_PATH}/
    ${ABS_SOURCE_PATH}/${SEC_MODEM_PATH}/sign_sec_modem.sh ${MODEM_INPUT_PATH} ${MODEM_OUTPUT_PATH} ${INI_FILE_PATH}
}
