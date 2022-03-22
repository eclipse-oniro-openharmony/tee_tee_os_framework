# file encry
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/file_encry
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/file_encry/sec_ufs_km.c
    platform/libthirdparty_drv/plat_drv/file_encry/sec_derive_key.c
    platform/libthirdparty_drv/plat_drv/file_encry/sec_ufs_key_drv.c
)