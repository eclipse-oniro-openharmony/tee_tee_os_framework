include $(TOPDIR)/libs/libplatdrv/platform/huanglong/mk/huanglong.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platform_module.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platform_mem.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platform_flags.mk
flags += $(TRUSTEDCORE_DEVCHIP_CFLAGS)
