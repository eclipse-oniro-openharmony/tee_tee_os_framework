# hifi
list(APPEND TEE_C_DEFINITIONS
    CONFIG_SUPPORT_HIFI_LOAD
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/include/hifi
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/hifi/hifi_reload.c
)