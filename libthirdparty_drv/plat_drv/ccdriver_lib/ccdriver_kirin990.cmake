# ccdriver_lib
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/cc_driver
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/cc_driver/cc712
)
list(APPEND TEE_C_SOURCES
    platform/common/cc_driver/cc712/cc_driver_adapt.c
    platform/libthirdparty_drv/plat_drv/ccdriver_lib/cc_power.c
    platform/libthirdparty_drv/plat_drv/ccdriver_lib/cc_adapt.c
    platform/common/cc_driver/cc_driver_hal.c
)
if (NOT "${product_type}" STREQUAL "armpc")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_USE_DUAL_ENGINE
    )
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/plat_drv/ccdriver_lib/eps_adapt.c
        platform/libthirdparty_drv/plat_drv/ccdriver_lib/eps_driver_hal.c
    )
endif()