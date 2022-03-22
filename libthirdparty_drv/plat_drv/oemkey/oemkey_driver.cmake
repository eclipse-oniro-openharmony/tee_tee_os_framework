list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/oemkey
)

#oem key
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/derive_teekey
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/common/plat_cap
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.c
    platform/common/plat_cap/plat_cap_hal.c
)
