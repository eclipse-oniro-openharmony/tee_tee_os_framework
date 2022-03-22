# gpio
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/gpio
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/gpio/gpio.c
)