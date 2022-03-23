#!/bin/bash
set -e

source ./cmake/clean.sh
source ./cmake/patch.sh
source ./cmake/config_function.sh
source ./cmake/generate_bootfs.sh
source ./cmake/single_sec_modem.sh

SOURCE_PATH=$(dirname $0)
ABS_SOURCE_PATH=$(cd ${SOURCE_PATH};pwd)
CMAKE_INSTALL_PREFIX=${ABS_SOURCE_PATH}/output
CMAKE_BUILD_PREFIX=${ABS_SOURCE_PATH}/build
OUT64=${CMAKE_BUILD_PREFIX}/out64
OUT32=${CMAKE_BUILD_PREFIX}/out32
OUT_MODEM=${ABS_SOURCE_PATH}/out_modem
HOST_OUT=${CMAKE_BUILD_PREFIX}/host_out
BOOTFS_OUT=${CMAKE_BUILD_PREFIX}/bootfs_out
PREBUILD_PATH=${ABS_SOURCE_PATH}/prebuild
CONFIG_FILE=${PREBUILD_PATH}/hm-teeos-local-release/headers/.config
TOOLCHAIN_FILE_64=clang64_toolchain.cmake
TARGET_BUILD_VARIANT=$(eval echo \$\{PATH\})
OUTPUTDIR_64=${OUT64}
OUTPUTDIR_32=${OUT32}
STAGE_DIR=${CMAKE_BUILD_PREFIX}/stage
BOOTFS_STAGE_DIR=${CMAKE_BUILD_PREFIX}/stage/bootfs
TEE_PATH=${ABS_SOURCE_PATH}/../../
parallel_threads=1
BUILD_TEST="n"
BUILD_TA_NAME="null"

if [ "$#" -eq 1 ] && [ "$1"x = "clean"x ]; then
    clean #do clean function
fi

while getopts "o:t:r:a:b:j:v:s:c:m" opt
do
    case "${opt}" in
        o) OBB_PRODUCT_NAME="$OPTARG" ;;
        t) TARGET_BOARD_PLATFORM="$OPTARG" ;;
        r) IMAGE_ROOT="$OPTARG" ;;
        a) product_type="$OPTARG" ;;
        j) parallel_threads="$OPTARG" ;;
        v) TARGET_BUILD_VARIANT="$OPTARG" ;;
        c) export chip_type="$OPTARG" ;;
        s) CFG_HISI_MINI_AP="$OPTARG" ;;
        m) BUILD_SINGLE_MOD="$OPTARG" ;;
        b)
        if [ "$OPTARG" != "null" ]  &&  [ "$OPTARG" != "" ] ; then
            BUILD_TEST="y"
            BUILD_TA_NAME="$OPTARG"
        fi;;
        \?) usage ;;
    esac
done

if [ ! -d "$PREBUILD_PATH"/hm-teeos-local-release ]; then
    echo "prebuild binaries are not ready yet!"
    exit 1
fi

check_for_arch

if [ "$USE_XOM32"x == "yx" ]
then
    TOOLCHAIN_FILE_32=clang32_toolchain_xom.cmake
else
    TOOLCHAIN_FILE_32=clang32_toolchain.cmake
fi

if [ -z "${IMAGE_ROOT}" ]; then
    IMAGE_ROOT=${ABS_SOURCE_PATH}/output
fi

HM_BRANCH=$(cat ${ABS_SOURCE_PATH}/../.git/HEAD | awk '{print $2}')
if [ "${HM_BRANCH}"x == "x" ]
then
    HM_BRANCH=$(cat ${ABS_SOURCE_PATH}/../.git/HEAD | awk '{print $1}')
    HMAPPS_COMMIT=$(echo "${HM_BRANCH}" | head -c 7)
else
    HM_COMMIT_ALL=$(cat ${ABS_SOURCE_PATH}/../.git/${HM_BRANCH})
    HMAPPS_COMMIT=$(echo "${HM_COMMIT_ALL}" | head -c 7)
fi

GCC_VERSION=$(gcc -dumpversion | cut -f1 -d.)
if [ $GCC_VERSION -ge 5 ]; then
    GCC_VERSION=1
else
    GCC_VERSION=0
fi

prepare()
{
    [ -n "${CMAKE_INSTALL_PREFIX}" ] && rm -rf ${CMAKE_INSTALL_PREFIX}
    [ -n "${CMAKE_BUILD_PREFIX}" ] && rm -rf ${CMAKE_BUILD_PREFIX}
    mkdir -p ${CMAKE_INSTALL_PREFIX}
    mkdir -p ${CMAKE_BUILD_PREFIX}
    mkdir -p ${HOST_OUT}
    mkdir -p ${OUT64}/headers/kirin/libc++
    mkdir -p ${OUT32}/headers/kirin/libc++
    mkdir -p ${STAGE_DIR}
    mkdir -p ${BOOTFS_STAGE_DIR}
    mkdir -p ${BOOTFS_OUT}
    mkdir -p ${OUT_MODEM}
}

prepare

if [ "$BUILD_SINGLE_MOD" == "true" ]; then
    compile_single_modem
else

    ###################
    # build ARCH host #
    ###################
    config_host & config_aarch64 & config_arm
    install_aarch64;install_arm
    compile_host & compile_aarch64 & compile_arm
    wait

    ##############################
    # prepare bins from prebuild #
    ##############################
    cmake --build . --target prepare_bins -j${parallel_threads}

    ###################
    # generate bootfs #
    ###################
    generate_bootfs
    clean_after_compile
fi
