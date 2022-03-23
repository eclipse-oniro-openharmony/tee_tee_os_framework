# hdcp for wifidisplay(wfd)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/hdcp_wfd
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/hdcp_wfd/hdcp_wfd.c
)