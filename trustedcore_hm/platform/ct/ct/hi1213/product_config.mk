export CONFIG_TA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_PLATDRV_64BIT := true
export CONFIG_DRV_TIMER_64BIT := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY :=true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_PERMSRV_64BIT := true

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
