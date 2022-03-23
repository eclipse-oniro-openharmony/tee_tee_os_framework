# secmem_ddr
COMPILE_SEC_DDR_TEST := false
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
#inc-flags += -DCONFIG_HISI_DDR_CA_RD
inc-flags += -DCONFIG_HISI_SEC_DDR_SUB_RGN
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/laguna_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/laguna/sec_region.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/laguna/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
	CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/laguna/sec_region_test.c
	inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif

