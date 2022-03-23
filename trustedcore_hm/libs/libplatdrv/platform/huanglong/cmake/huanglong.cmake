list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/src/cclib
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pal
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
)

list(APPEND TEE_C_FLAGS
    -DDX_ENABLE=1
)

if ("${CONFIG_TERMINAL_DRV_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc63
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/huanglong
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/include
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/common
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/npu/include
        ${PROJECT_SOURCE_DIR}/sys_libs/libtimer/include
        ${PREBUILD_DIR}/headers/ddk/legacy
        ${PREBUILD_DIR}/headers/inner_sdk/teeapi
        ${PREBUILD_DIR}/headers/sdk/gpapi
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc63/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/huanglong/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/ccdriver_lib/keyservice.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/ccdriver_lib/cc_driver_syscall.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
    )
include (${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/itrustee.cmake)
endif()
