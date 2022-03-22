if ("${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore")
list(APPEND TEE_C_DEFINITIONS
    TEE_SUPPORT_SECISP
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/baltimore
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv_key/isp/hisp_mem.c
    platform/libthirdparty_drv/plat_drv_key/isp/hisp_load.c
    platform/libthirdparty_drv/plat_drv_key/isp/hisp_secboot.c
    platform/libthirdparty_drv/plat_drv_key/isp/baltimore/hisp_pwr.c
    platform/libthirdparty_drv/plat_drv_key/isp/baltimore/hisp.c
)
if ("${chip_type}" STREQUAL "es")
list(APPEND TEE_C_DEFINITIONS
    ISP_CHIP_ES
)
endif()
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_SUPPORT_ISP_LOAD
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
)
if (NOT "${product_type}" STREQUAL "armpc")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_ISP_SEC_IMAGE
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
)
endif()
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "denver" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "laguna")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_ISP_SEC_IMAGE
    CONFIG_SUPPORT_ISP_LOAD
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
)
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "burbank" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "kirin970" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980" OR "${TARGET_BOARD_PLATFORM}" STREQUAL "kirin710" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "orlando")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_SUPPORT_ISP_LOAD
    CONFIG_HISI_ISP_SEC_IMAGE
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/revisions
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv_key/isp/revisions/hisp.c
)
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "miamicw")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_SUPPORT_ISP_LOAD
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/isp
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/isp/revisions
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
)
endif()