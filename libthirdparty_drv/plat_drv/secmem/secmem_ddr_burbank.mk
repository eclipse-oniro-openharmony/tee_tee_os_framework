COMPILE_SEC_DDR_TEST := false
inc-flags += -DDDR_TWO_CHANNEL
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_CA_RD
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/driver/include
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/burbank_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/burbank/sec_region.c
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/burbank/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
	CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/burbank/sec_region_test.c
	inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif
