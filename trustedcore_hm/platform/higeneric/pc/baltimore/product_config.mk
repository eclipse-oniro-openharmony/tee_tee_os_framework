export CONFIG_TA_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_RPMB_64BIT := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_RESUME_FREE_TIMER := true
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DX_ENABLE := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_SSA_64BIT := true
export CONFIG_TIMER_S3_ADJUST_FREQ := true
export CONFIG_PERMSRV_64BIT := true
#export ENABLE_TA_LOAD_WHITE_BOX_KEY := true
arm_chip_apps += file_encry
arm_ext_apps := bdkernel
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/file_encry.elf \
		$(OUTPUTDIR)/arm/apps/bdkernel.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/file_encry.elf \
		$(OUTPUTDIR)/aarch64/apps/bdkernel.elf
endif
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
