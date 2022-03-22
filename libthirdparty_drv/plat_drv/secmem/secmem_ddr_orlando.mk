inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET

CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/orlando_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/orlando/sec_region.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/orlando/tzmp2.c
inc-flags += -DCONFIG_HISI_DDR_SEC_IDENTIFICATION
inc-flags += -DCONFIG_HISI_DDR_SEC_TUI
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

