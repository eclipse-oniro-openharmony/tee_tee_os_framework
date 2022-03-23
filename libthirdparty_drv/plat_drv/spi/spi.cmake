# spi
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/spi
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/spi/plat/${TARGET_BOARD_PLATFORM}
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/spi/spi.c
)