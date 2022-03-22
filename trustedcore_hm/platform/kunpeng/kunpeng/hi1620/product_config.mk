export CONFIG_TA_64BIT := true
export CONFIG_GTASK_64BIT := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_PLATDRV_64BIT := true
export CONFIG_DRV_TIMER_64BIT := true
export CONFIG_PERMSRV_64BIT := true
export CONFIG_GMLIB_IMPORT := false
export CONFIG_KUNGPENG_SEC_ENABLE := true
export CONFIG_TRNG_ENABLE := true
export CONFIG_CLOUD_CA_PUB_KEY := true
export CONFIG_CLOUD_SIGN_PUB_KEY := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_BOOT_ARGS_TRANSFER := true
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
