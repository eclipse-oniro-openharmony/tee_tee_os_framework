# tzpc
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/tzpc
)
list(APPEND TEE_C_SOURCES
    platform/common/tzpc/tzpc_cfg.c
)

if ("${PRODUCT_RANGE}" STREQUAL "base")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_TZPC_BASE
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tzpc/${TARGET_BOARD_PLATFORM}
)
endif()