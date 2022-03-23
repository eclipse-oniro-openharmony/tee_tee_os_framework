export CONFIG_TUI_32BIT := false
export CONFIG_TA_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_RPMB_64BIT := true
export CONFIG_SEM := false
export CONFIG_SE_SERVICE_64BIT := false
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GATEKEEPER_32BIT := true
export CONFIG_KEYMASTER_32BIT := true
export CONFIG_ANTIROOT := false
export CONFIG_WEAVER := false
export CONFIG_PERMSRV_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export CONFIG_DX_ENABLE := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_VLTMM_SRV:= true
export TEE_SUPPORT_FILE_ENCRY_V3 := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY := true

# base indicate A pkg
ifneq ($(PRODUCT_RANGE), base)
# mspe dont compile in A pkg
export FEATURE_HISI_MSP_ENGINE_LIBCRYPTO := true
export CONFIG_HISI_MSPE_SMMUV2 := y
export CONFIG_HISI_MSPE_POWER_SCHEME := y
export CONFIG_HISI_MSPE_IN_MEDIA2 := y
endif

arm_chip_apps += secmem file_encry
arm_ext_apps += vltmm_service
arm_tee_mods += sec_modem
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/secmem.elf \
                $(OUTPUTDIR)/arm/apps/vltmm_service.elf \
                $(OUTPUTDIR)/arm/apps/file_encry.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/hivcodec.elf \
              $(OUTPUTDIR)/aarch64/apps/file_encry.elf \
              $(OUTPUTDIR)/aarch64/apps/secmem.elf \
              $(OUTPUTDIR)/aarch64/apps/bdkernel.elf \
              $(OUTPUTDIR)/aarch64/apps/vltmm_service.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
