# vcodec
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/include/
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/
)
list(APPEND TEE_C_SOURCES
#    platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/sec_intf.c
    platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/venc_tee.c
    platform/libthirdparty_drv/plat_drv_key/vcodec/hi_vcodec/venc_hivna/venc_phoenix.c
)