# secmem_ddr
list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_DDR_AUTO_FSGT
    CONFIG_HISI_DDR_SEC_CFC
    CONFIG_HISI_DDR_SEC_HIFI_RESET
    CONFIG_HISI_DDR_CA_RD
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990_ddr_autofsgt_proxy_secure_os.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/sec_region.c
    platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/tzmp2.c
)
if ("${COMPILE_SEC_DDR_TEST}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/sec_region_test.c
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_SEC_DDR_TEST
    )
endif()