if ("${WITH_MODEM}" STREQUAL "true")
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/modem/icc
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/modem/include
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/adp/adp_icc.c
    platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_call.c
    platform/libthirdparty_drv/plat_drv/modem/adp/bsp_param_cfg.c
    platform/libthirdparty_drv/plat_drv/modem/adp/bsp_secboot_adp.c
    platform/libthirdparty_drv/plat_drv/modem/icc/ipc_core.c
    platform/libthirdparty_drv/plat_drv/modem/icc/icc_core.c
    platform/libthirdparty_drv/plat_drv/modem/icc/icc_debug.c
    platform/libthirdparty_drv/plat_drv/modem/icc/icc_secos.c
)
# trng
list(APPEND TEE_C_DEFINITIONS
    CONFIG_MODEM_TRNG
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/trng/trng_seed.c
)

# secboot
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info.c
)

# without modem
else()
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/adp/bsp_modem_stub.c
    platform/libthirdparty_drv/plat_drv/secureboot/process_modem_info_stub.c
)
endif()