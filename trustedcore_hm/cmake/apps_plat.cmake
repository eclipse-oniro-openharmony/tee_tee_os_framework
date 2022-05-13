# platform compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

if(NOT TARGET_BOARD_PLATFORM STREQUAL "")

set(TRUSTEDCORE_CHIP_CHOOSE 0)
set(TRUSTEDCORE_PLATFORM_CHOOSE 0)

include(${PLATFORM_DIR}/../cmake/plat/${TARGET_BOARD_PLATFORM}/plat.cmake)

# if chip.cmake exist, include chip.cmake
if(PRODUCT_NAME STREQUAL "")
    if (EXISTS ${PLATFORM_DIR}/${PLATFORM_NAME}/${CHIP_NAME}/chip.cmake)
        include(${PLATFORM_DIR}/${PLATFORM_NAME}/${CHIP_NAME}/chip.cmake)
    endif()
    if (EXISTS ${PLATFORM_DIR}/${PLATFORM_NAME}/common/chip.cmake)
        include(${PLATFORM_DIR}/${PLATFORM_NAME}/common/chip.cmake)
    endif()
else()
    if (EXISTS ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/chip.cmake)
        include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/chip.cmake)
    endif()
    if (EXISTS ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/chip.cmake)
        include(${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/chip.cmake)
    endif()
endif()


include(apps_asan)

list(APPEND TRUSTEDCORE_PLATFORM_FLAGS
    -DHMAPPS_COMMIT_ID=${HMAPPS_COMMIT}
    -DTRUSTEDCORE_CHIP_CHOOSE=${TRUSTEDCORE_CHIP_CHOOSE}
    -DTRUSTEDCORE_PLATFORM_CHOOSE=${TRUSTEDCORE_PLATFORM_CHOOSE}
)
endif()
