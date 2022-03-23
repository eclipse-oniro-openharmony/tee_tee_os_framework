COMPILE_SEC_DDR_TEST := false
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_CA_RD
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/sec_region.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
	CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/kirin990/sec_region_test.c
	inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif
