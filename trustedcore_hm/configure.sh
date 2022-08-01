#!/bin/bash
set -e

SOURCE_PATH=$(dirname $0)
ABS_SOURCE_PATH=$(cd ${SOURCE_PATH};pwd)
OUT64=${ABS_SOURCE_PATH}/out64
OUT32=${ABS_SOURCE_PATH}/out32
HOST_OUT=${ABS_SOURCE_PATH}/host_out
BOOTFS_OUT=${ABS_SOURCE_PATH}/bootfs_out
PREBUILD_PATH=${ABS_SOURCE_PATH}/prebuild
CONFIG_FILE=${PREBUILD_PATH}/hm-teeos-local-release/headers/.config
TOOLCHAIN_FILE_64=clang64_toolchain.cmake
TOOLCHAIN_FILE_32=clang32_toolchain.cmake
TARGET_BUILD_VARIANT=$(eval echo \$\{PATH\})
OUTPUTDIR_64=${OUT64}
OUTPUTDIR_32=${OUT32}
STAGE_DIR=${ABS_SOURCE_PATH}/stage
BOOTFS_STAGE_DIR=${ABS_SOURCE_PATH}/stage/bootfs
TEE_PATH=${ABS_SOURCE_PATH}/../../
parallel_threads=1

clean_after_compile()
{
    set -x
    ${ABS_SOURCE_PATH}/../../hm-teeos/libs/syslib/libc/clean_libc.sh  ${ABS_SOURCE_PATH}/../../hm-teeos
    ${ABS_SOURCE_PATH}/../../hm-teeos/libs/syslib/libc++/clean_libcxx.sh  ${ABS_SOURCE_PATH}/../../hm-teeos
    ${ABS_SOURCE_PATH}/../../hm-teeos/libs/teelib/libcompiler-rt/clean_compiler-rt.sh ${ABS_SOURCE_PATH}/../../hm-teeos
    rm ${ABS_SOURCE_PATH}/tools/cpio-strip/cpio-strip
    set +x
}

clean()
{
    clean_after_compile
    set -x
    rm -rf ${HOST_OUT}
    rm -rf ${OUT64}
    rm -rf ${OUT32}
    rm -rf ${BOOTFS_OUT}
    rm -rf ${STAGE_DIR}
    set +x
    exit 0
}

if [ "$#" -eq 1 ] && [ "$1"x = "clean"x ]; then
    clean
fi

while getopts "o:t:r:a:j:" opt
do
    case "${opt}" in
        o)
            OBB_PRODUCT_NAME="$OPTARG"
            ;;
        t)
            TARGET_BOARD_PLATFORM="$OPTARG"
            ;;
        r)
            IMAGE_ROOT="$OPTARG"
            ;;
        a)
            product_type="$OPTARG"
            ;;
        j)
           parallel_threads="$OPTARG"
           ;;
        \?)
            usage
            ;;
    esac
done

usage()
{
    echo "Example:"
    echo "    ./configure.sh -o kirin990 -t kirin990"

}

check_for_arch()
{
    while read line;
    do
        echo $line;
        var=${line%=*}
        val=${line#*=}

        echo "var = ${var}, val = ${val}"

        if [ "$var" == "CONFIG_ARCH_AARCH64" ] && [ "$val" == "y" ]; then
            ARCH=aarch64
        fi

        if [ "$var" == "CONFIG_ARCH_AARCH32" ] && [ "$val" == "y" ]; then
            ARCH=arm
        fi

        if [ -n "$ARCH" ] && [ -n "$USE_XOM32" ]; then
            break
        fi
    done < ${CONFIG_FILE} &> /dev/null

    if [ -z ${ARCH} ]; then
        echo "ERROR: ARCH is not set" 2>&1
        exit 1
    fi
}

if [ ! -d "$PREBUILD_PATH"/hm-teeos-local-release ]; then
    echo "prebuild binaries are not ready yet!"
    exit 1
fi

check_for_arch

if [ -z ${IMAGE_ROOT} ]; then
    IMAGE_ROOT=${ABS_SOURCE_PATH}
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

apply_openssl_patch()
{
    crypto_path=${ABS_SOURCE_PATH}/open_source/OpenSSL/openssl-1.1.1f/crypto
    checkpatch=${ABS_SOURCE_PATH}/open_source/OpenSSL/openssl-1.1.1f/include/openssl/opensslconf.h
    if [ ! -e "$checkpatch" ]; then
        cd ${ABS_SOURCE_PATH}/open_source/OpenSSL
        patch -p3 < huawei_resolve_crypto_compile_001.patch
        patch -p3 < huawei_replace_rand_generation_002.patch
        patch -p3 < huawei_resolve_ui_dependency_003.patch
        patch -p3 < huawei_resolve_memset_link_004.patch
        patch -p3 < huawei_delete_ec448_keccak1600_kdf_005.patch
        patch -p3 < huawei_config_ec25519_006.patch
        patch -p3 < huawei_xom_64_007.patch
        patch -p3 < huawei_xom_64_008.patch
        patch -p3 < huawei_xom_64_009.patch
        patch -p3 < huawei_performance_optimization_010.patch
        patch -p5 -d openssl-1.1.1f/ < openssl-1.1.1f-CVE-2020-1967.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2020-1971-Correctly-compare-EdiPartyName-in-GENERAL_N-c.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-23840-fix-output-length-overflow.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-23841-fix-Null-pointer-deref.patch
        patch -p1 -d openssl-1.1.1f/ < Backport-CVE-2021-3449-ssl-sigalg-extension-fix-NULL-pointer-deref-c.patch
    fi
    checkpatch=${ABS_SOURCE_PATH}/open_source/OpenSSL/openssl-1.1.1f/crypto/aes/asm/aes-armv4.S
    if [ ! -e "$checkpatch" ]; then
        cd ${ABS_SOURCE_PATH}/open_source/OpenSSL
        /usr/bin/perl $crypto_path/aes/asm/aes-armv4.pl linux32 $crypto_path/aes/asm/aes-armv4.S
        /usr/bin/perl $crypto_path/aes/asm/bsaes-armv7.pl linux32 $crypto_path/aes/asm/bsaes-armv7.S
        /usr/bin/perl $crypto_path/aes/asm/aesv8-armx.pl linux64 $crypto_path/aes/asm/aesv8-armx.S
        /usr/bin/perl $crypto_path/aes/asm/vpaes-armv8.pl linux64 $crypto_path/aes/asm/vpaes-armv8.S
        /usr/bin/perl $crypto_path/bn/asm/armv4-mont.pl linux32 $crypto_path/bn/asm/armv4-mont.S
        /usr/bin/perl $crypto_path/bn/asm/armv4-gf2m.pl linux32 $crypto_path/bn/asm/armv4-gf2m.S
        /usr/bin/perl $crypto_path/bn/asm/armv8-mont.pl linux64 $crypto_path/bn/asm/armv8-mont.S
        /usr/bin/perl $crypto_path/ec/asm/ecp_nistz256-armv4.pl linux32 $crypto_path/ec/asm/ecp_nistz256-armv4.S
        /usr/bin/perl $crypto_path/ec/asm/ecp_nistz256-armv8.pl linux64 $crypto_path/ec/asm/ecp_nistz256-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/keccak1600-armv4.pl linux32 $crypto_path/sha/asm/keccak1600-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/sha1-armv4-large.pl linux32 $crypto_path/sha/asm/sha1-armv4-large.S
        /usr/bin/perl $crypto_path/sha/asm/sha256-armv4.pl linux32 $crypto_path/sha/asm/sha256-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv4.pl linux32 $crypto_path/sha/asm/sha512-armv4.S
        /usr/bin/perl $crypto_path/sha/asm/keccak1600-armv8.pl linux64 $crypto_path/sha/asm/keccak1600-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha1-armv8.pl linux64 $crypto_path/sha/asm/sha1-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv8.pl linux64 $crypto_path/sha/asm/sha256-armv8.S
        /usr/bin/perl $crypto_path/sha/asm/sha512-armv8.pl linux64 $crypto_path/sha/asm/sha512-armv8.S
        /usr/bin/perl $crptopath/modes/asm/ghashv8-armx.pl linux64 $crptopath/modes/asm/ghashv8-armx.S
        /usr/bin/perl $crptopath/modes/asm/ghash-armv4.pl linux32 $crptopath/modes/asm/ghash-armv4.S
        /usr/bin/perl $crptopath/armv4cpuid.pl linux32 $crptopath/armv4cpuid.S
        /usr/bin/perl $crptopath/arm64cpuid.pl linux64 $crptopath/arm64cpuid.S
    fi
}

prepare()
{
    rm -rf ${HOST_OUT}
    rm -rf ${OUT64}
    rm -rf ${OUT32}
    rm -rf ${BOOTFS_OUT}
    rm -rf ${STAGE_DIR}
    mkdir -p ${HOST_OUT}
    mkdir -p ${OUT64}
    mkdir -p ${OUT64}/headers/kirin
    mkdir -p ${OUT64}/headers/kirin/libc++
    mkdir -p ${OUT32}
    mkdir -p ${OUT32}/headers/kirin
    mkdir -p ${OUT32}/headers/kirin/libc++
    mkdir -p ${STAGE_DIR}
    mkdir -p ${BOOTFS_STAGE_DIR}
    mkdir -p ${BOOTFS_OUT}
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
        -Dproduct_type=${product_type} \
        -DGCC_VERSION=${GCC_VERSION} \
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
        -Dproduct_type=${product_type} \
        -DHOST_BINS_DIR=${STAGE_DIR} \
        -DBUILD_KERNEL=${BUILD_KERNEL} \
        -DGET_XOM_FILE=${GET_XOM_FILE} \
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
        -Dproduct_type=${product_type} \
        -DHOST_BINS_DIR=${STAGE_DIR} \
        -DUSE_XOM32=${USE_XOM32} \
        -DBUILD_KERNEL=${BUILD_KERNEL} \
        -DGET_XOM_FILE=${GET_XOM_FILE} \
        ${ABS_SOURCE_PATH}
}

prepare

###################
# build ARCH host #
###################
cd ${HOST_OUT}

configure_host
cmake --build . --target release_host -j${parallel_threads}
cmake -DCOMPONENT=bins_install -P cmake_install.cmake

######################
# build ARCH aarch64 #
######################
cd ${OUT64}

configure_aarch64
cmake --build . --target install_headers_64 -j${parallel_threads}
cmake --build . --target release_64 -j${parallel_threads}
cmake --build . --target check_symbols -j${parallel_threads}
cmake -DCOMPONENT=bins_install -P cmake_install.cmake
cmake -DCOMPONENT=libs_install -P cmake_install.cmake
##################
# build ARCH arm #
##################

cd ${OUT32}

configure_arm
cmake --build . --target install_headers_32 -j${parallel_threads}
cmake --build . --target release_32 -j${parallel_threads}
cmake --build . --target check_symbols -j${parallel_threads}
cmake -DCOMPONENT=bins_install -P cmake_install.cmake
cmake -DCOMPONENT=libs_install -P cmake_install.cmake

##############################
# prepare bins from prebuild #
##############################
cmake --build . --target prepare_bins -j${parallel_threads}

###################
# generate bootfs #
###################

cd ${BOOTFS_OUT}

GET_XOM_FILE="true"
if [ "$ARCH" = "aarch64" ]; then
    configure_aarch64
else
    configure_arm
fi

if [ "$USE_XOM32"x == yx ]; then
    cmake --build . --target use_xom32 -j${parallel_threads}
    cmake --build . --target remove_xomloc_section -j${parallel_threads}
fi
cmake --build . --target scramble_bootfs_symbols -j${parallel_threads}
cmake --build . --target bootfs -j${parallel_threads}

if [ "$ARCH" = "aarch64" ]; then
    cd ${OUT64}
else
    cd ${OUT32}
fi

cmake --build . --target hmfilemgr -j${parallel_threads}
if [ "$USE_XOM32"x == yx ]; then
    cmake --build . --target use_xom32_hmfilemgr -j${parallel_threads}
    cmake --build . --target remove_xomloc_section_hmfilemgr -j${parallel_threads}
    cmake --build . --target use_xom32_hmsysmgr -j${parallel_threads}
    cmake --build . --target remove_xomloc_section_hmsysmgr -j${parallel_threads}
fi
cmake --build . --target scramble_hmfilemgr_symbols -j${parallel_threads}
cmake --build . --target scramble_hmsysmgr_symbols -j${parallel_threads}
cmake --build . --target gen_trustedcore_image -j${parallel_threads}
clean_after_compile
