# teeos shared memory
list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tee_sharedmem/bl2_sharedmem.c
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/tee_sharedmem
)