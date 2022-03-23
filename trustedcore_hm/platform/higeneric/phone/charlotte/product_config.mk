export CONFIG_TUI_32BIT := false
export CONFIG_TA_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_RPMB_64BIT := true
export CONFIG_SEM := false
export CONFIG_SE_SERVICE_64BIT := true
export ENABLE_CPP := false
export ENABLE_CPP_STATIC := false
export CONFIG_GATEKEEPER_64BIT := true
export CONFIG_KEYMASTER_64BIT := true
export CONFIG_ANTIROOT := false
export CONFIG_WEAVER := false
export CONFIG_PERMSRV_64BIT := true
export CONFIG_PLATDRV_64BIT := true
export CONFIG_DRV_TIMER_64BIT := true
export CONFIG_DRV_64BIT := true
export CONFIG_DX_ENABLE := false
export CONFIG_GMLIB_IMPORT := true
export CONFIG_HUK_SERVICE_64BIT := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY := true

arm_chip_apps +=
arm_ext_apps +=
product_apps +=

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
