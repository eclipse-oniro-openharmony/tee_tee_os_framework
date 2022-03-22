include(${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/modem/modem_common.cmake)
if ("${WITH_MODEM}" STREQUAL "true")
if ("${chip_type}" STREQUAL "cs2")
list(APPEND TEE_C_DEFINITIONS
    CONFIG_MLOADER
    CONFIG_MODEM_COLD_PATCH
    CONFIG_COLD_PATCH_BORROW_DDR
    CONFIG_MODEM_ASLR_5G_CORE
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_aslr.c
    platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_patch.c
    platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump_plat.c
)
else()
list(APPEND TEE_C_DEFINITIONS
    CONFIG__COLD_PATCH
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump.c
)
endif()
if (NOT "${cust_config}" STREQUAL "cust_modem_asan")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_MODEM_BALONG_ASLR
    )
endif()
endif()