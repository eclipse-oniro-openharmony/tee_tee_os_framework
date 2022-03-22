export CONFIG_TUI_32BIT := true
export CONFIG_TA_64BIT := true
export CONFIG_SSA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_RPMB_64BIT := true
export CONFIG_SEC_FLASH := true
export CONFIG_SEM := true
export CONFIG_SE_SERVICE_64BIT := true
export CONFIG_MSP := true
export CONFIG_BIO := true
export CONFIG_ROT := true
export CONFIG_ART := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GATEKEEPER_64BIT := true
export CONFIG_KEYMASTER_64BIT := true
export CONFIG_ANTIROOT := true
export CONFIG_EPS_FOR_MSP := true
export CONFIG_HISI_MSPC := true
export FEATURE_HISI_MSP_ENGINE_LIBCRYPTO := true
export TEE_SUPPORT_FILE_ENCRY_V3 := true
export CONFIG_FILE_ENCRY_USING_RPMB := true
export TEE_SUPPORT_MSP := true
export CONFIG_GENERIC_ROT:= true
export CONFIG_GENERIC_ART:= true
export CONFIG_HISI_BIOMETRIC:= true
export CONFIG_WEAVER := true
export CONFIG_HISI_MSP_SECFLASH:= true
export CONFIG_VLTMM_SRV:= true
export CONFIG_PERMSRV_64BIT := true
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := true
export CONFIG_DRV_64BIT := false
export CONFIG_HISI_PRIVACY_PROTECTION := true
export CONFIG_HISI_MSPC_IPC_TEST := false
#export ENABLE_TA_LOAD_WHITE_BOX_KEY := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DX_ENABLE := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_HISI_MSPE_SMMUV3 := y
# Seplat external library targets
ifeq ($(seplat), london)
export CONFIG_FEATURE_SEPLAT := true
export CONFIG_TEE_LIBSEPLAT_EXTERNAL := true
endif

arm_chip_apps := secmem rot file_encry art biometric secisp
arm_ext_apps := hivcodec_sr bdkernel vltmm_service hwsdp
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/secmem.elf \
                $(OUTPUTDIR)/arm/apps/file_encry.elf \
                $(OUTPUTDIR)/arm/apps/rot.elf \
                $(OUTPUTDIR)/arm/apps/art.elf \
                $(OUTPUTDIR)/arm/apps/bdkernel.elf \
                $(OUTPUTDIR)/arm/apps/biometric.elf \
                $(OUTPUTDIR)/arm/apps/secisp.elf \
                $(OUTPUTDIR)/arm/apps/hivcodec_sr.elf \
                $(OUTPUTDIR)/arm/apps/vltmm_service.elf \
                $(OUTPUTDIR)/arm/apps/hwsdp.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/secmem.elf \
                $(OUTPUTDIR)/aarch64/apps/file_encry.elf \
                $(OUTPUTDIR)/aarch64/apps/rot.elf \
                $(OUTPUTDIR)/aarch64/apps/art.elf \
                $(OUTPUTDIR)/aarch64/apps/bdkernel.elf \
                $(OUTPUTDIR)/aarch64/apps/biometric.elf \
                $(OUTPUTDIR)/aarch64/apps/secisp.elf \
                $(OUTPUTDIR)/aarch64/apps/hivcodec_sr.elf \
                $(OUTPUTDIR)/aarch64/apps/vltmm_service.elf \
                $(OUTPUTDIR)/aarch64/apps/hwsdp.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
