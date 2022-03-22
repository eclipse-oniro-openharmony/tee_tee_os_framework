#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
set -e

# set base build
BUILD_ROOT=$(cd $(dirname "$0")&&pwd)
export ANDROID_TOP_ABS_DIR=$(cd "${BUILD_ROOT}/../../../../../../../../.."&&pwd)
export HI_PLATFORM="teeos"
export HI_TARGET="libseceng"
source "${BUILD_ROOT}/build/build_hieps.sh"

# build libseceng
func_init_variable "$@"
func_config
func_build "$@"
rm -rf "${BUILD_ROOT}/out" 2>/dev/null

# build image
export HI_TARGET="libcrypto"
export HI_SELF_MAKE="false"
export HI_TEEOS_COMPILE="true"
export TARGET_BUILD_VARIANT="eng"
if [ "${HI_DFT_ENABLE}" != "true" ]; then
	export TARGET_BUILD_VARIANT="user"
fi
cd "${MK_PROJ_ROOT_DIR}"
rm -rf "${ANDROID_TOP_ABS_DIR}/obj" 2>/dev/null
make clean
export TARGET_BOARD_PLATFORM="${HI_CHIP_NAME}" && export OBB_PRODUCT_NAME="${HI_CHIP_NAME}" && export chip_type="${HI_CHIP_TYPE}" && make && rm -rf ../../hisi/vrl_creater_for_local/*trustedcore.img && cp -rf output/stage/kirin/trustedcore.img ../../hisi/vrl_creater_for_local/ && cd ../../hisi/vrl_creater_for_local && chmod +x create_cert.sh && ./create_cert.sh trustedcore trustedcore.img "$TARGET_BOARD_PLATFORM" && cd - && cp -rf ../../hisi/vrl_creater_for_local/*trustedcore.img ./
