ifeq ($(filter $(ap_cust_spec), 2g_mem), )
export CONFIG_TUI_32BIT := true
endif
export CONFIG_TA_64BIT := false
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_RPMB_64BIT := false
export CONFIG_SEM := true
export CONFIG_SE_SERVICE_32BIT := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GATEKEEPER_32BIT := true
export CONFIG_KEYMASTER_32BIT := true
export CONFIG_ANTIROOT := true
export CONFIG_WEAVER := true
export CONFIG_PERMSRV_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DX_ENABLE := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true

arm_chip_apps += secmem
arm_ext_apps += hivcodec bdkernel
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/secmem.elf \
		$(OUTPUTDIR)/arm/apps/hivcodec.elf \
		$(OUTPUTDIR)/arm/apps/bdkernel.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/secmem.elf \
		$(OUTPUTDIR)/aarch64/apps/hivcodec.elf \
		$(OUTPUTDIR)/aarch64/apps/bdkernel.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
