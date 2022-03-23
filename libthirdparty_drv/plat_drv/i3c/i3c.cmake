# i3c
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/i3c
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/i3c/i3c.c
)