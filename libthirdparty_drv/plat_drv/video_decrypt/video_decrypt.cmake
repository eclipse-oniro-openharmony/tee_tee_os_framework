# video decrypt
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv_key
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/huawei_drv
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/video_decrypt/vdec_mmap.c
)

# vdec-video_decoder
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/video_decrypt
)