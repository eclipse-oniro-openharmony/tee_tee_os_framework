export CONFIG_TA_64BIT := false
export CONFIG_TA_32BIT := true
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_RPMB_64BIT := false
export CONFIG_SEM := false
export CONFIG_GATEKEEPER_32BIT := false
export CONFIG_KEYMASTER_32BIT := false
export CONFIG_ANTIROOT := false
export CONFIG_PERMSRV_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export ENABLE_TA_LOAD_WHITE_BOX_KEY :=true
export CONFIG_GMLIB_IMPORT := false
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true

arm_ext_apps += kds
product_apps += $(OUTPUTDIR)/arm/apps/kds.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
