include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/modem_common.mk

ifeq ($(WITH_MODEM), true)
inc-flags += -DCONFIG_COLD_PATCH
inc-flags += -DCONFIG_MODEM_BALONG_ASLR
endif