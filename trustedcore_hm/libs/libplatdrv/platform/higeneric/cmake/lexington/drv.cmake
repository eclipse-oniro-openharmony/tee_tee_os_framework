set(USE_GNU_CXX y)
list(APPEND PLATDRV_LIBRARIES
    bz_hm
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/lexington
    ${PROJECT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem
)

list(APPEND TEE_C_DEFINITIONS
    TEMP_API_WITHOUT_ISP
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/src/temp_apis.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/seccfg/hisi_hwspinlock.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem/bl2_sharedmem.c
)

# oemkey
include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        DX_ENABLE=1
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/platform/common/cc_driver
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/platform/common/cc_driver/cc712
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_power.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/antiroot/nonsecure_hasher.c
    )
endif()
