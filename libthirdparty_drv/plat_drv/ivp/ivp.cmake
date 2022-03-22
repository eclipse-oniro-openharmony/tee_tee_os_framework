# ivp
list(APPEND TEE_C_DEFINITIONS
    SEC_IVP
    CHECK_DDR_SEC_CONFIG
)
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/ivp
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/ivp/hivp.c
)