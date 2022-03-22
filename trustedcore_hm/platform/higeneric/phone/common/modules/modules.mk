ifneq ($(findstring true, $(CONFIG_TUI_64BIT)$(CONFIG_TUI_32BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/tui.mk
endif
ifeq ($(CONFIG_SEC_FLASH), true)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/sec_flash.mk
endif
ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT) $(CONFIG_SE_SERVICE_64BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/se_service.mk
endif
ifneq ($(findstring true, $(CONFIG_GATEKEEPER_32BIT)$(CONFIG_GATEKEEPER_64BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/gatekeeper.mk
endif
ifneq ($(findstring true, $(CONFIG_KEYMASTER_32BIT)$(CONFIG_KEYMASTER_64BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/keymaster.mk
endif
ifeq ($(CONFIG_SEM), true)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/sem.mk
endif
ifeq ($(CONFIG_ANTIROOT), true)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/antiroot.mk
endif
