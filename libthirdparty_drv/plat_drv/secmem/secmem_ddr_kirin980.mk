inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_SEC_CFG

CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin980_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/sec_region.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/tzmp2.c
inc-flags += -DCONFIG_HISI_DDR_SEC_IDENTIFICATION
