export CONFIG_TUI_32BIT := true
export CONFIG_TA_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_RPMB_64BIT := true
export CONFIG_SEC_FLASH := true
export CONFIG_SEM := true
export CONFIG_SE_SERVICE_64BIT := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GATEKEEPER_64BIT := true
export CONFIG_KEYMASTER_64BIT := true
export CONFIG_ANTIROOT := true
ifneq ($(product_type), armpc)
export FEATURE_HISI_HIEPS := true
export CONFIG_EPS_FOR_990 := true
else
export CONFIG_RESUME_FREE_TIMER := true
endif
export CONFIG_HISI_SECFLASH:= true
export CONFIG_WEAVER := true
export CONFIG_PERMSRV_64BIT := true
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := true
export CONFIG_DRV_64BIT := false
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DX_ENABLE := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_TEE_DRV_SERVER_64BIT := true
export CONFIG_DYN_CONF := true

ifeq ($(product_type),cdc)
export CONFIG_TIMER_S3_ADJUST_FREQ := true
endif

arm_chip_apps += secmem file_encry
arm_ext_apps := hivcodec bdkernel
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/secmem.elf \
		$(OUTPUTDIR)/arm/apps/file_encry.elf \
		$(OUTPUTDIR)/arm/apps/hivcodec.elf \
		$(OUTPUTDIR)/arm/apps/bdkernel.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/secmem.elf \
		$(OUTPUTDIR)/aarch64/apps/file_encry.elf \
		$(OUTPUTDIR)/aarch64/apps/hivcodec.elf \
		$(OUTPUTDIR)/aarch64/apps/bdkernel.elf
endif
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
