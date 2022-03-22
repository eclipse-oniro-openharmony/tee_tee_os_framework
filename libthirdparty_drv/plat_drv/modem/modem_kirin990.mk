include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/modem_common.mk

ifeq ($(WITH_MODEM), true)

ifeq ($(chip_type), cs2)
inc-flags += -DCONFIG_MLOADER
inc-flags += -DCONFIG_MODEM_COLD_PATCH
inc-flags += -DCONFIG_COLD_PATCH_BORROW_DDR
inc-flags += -DCONFIG_MODEM_ASLR_5G_CORE
CFILES += platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_aslr.c \
	  platform/libthirdparty_drv/plat_drv/secureboot/hisi_secboot_modem_patch.c \
	  platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump_plat.c
else
inc-flags += -DCONFIG_COLD_PATCH
CFILES += platform/libthirdparty_drv/plat_drv/modem/adp/sec_modem_dump.c
endif

ifneq ($(cust_config), cust_modem_asan)
inc-flags += -DCONFIG_MODEM_BALONG_ASLR
endif

endif