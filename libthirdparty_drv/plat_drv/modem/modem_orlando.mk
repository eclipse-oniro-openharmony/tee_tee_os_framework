include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/modem_common.mk

ifeq ($(WITH_MODEM), true)
inc-flags += -DBALONG_MODEM_CERT
inc-flags += -DCONFIG_COLD_PATCH
inc-flags += -DCONFIG_MODEM_BALONG_ASLR

CFILES += platform/kirin/modem/adp/sec_modem_dump.c
endif