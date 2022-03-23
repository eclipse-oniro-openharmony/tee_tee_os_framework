ifneq ($(findstring true, $(CONFIG_TUI_64BIT)$(CONFIG_TUI_32BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/tui.mk
endif
