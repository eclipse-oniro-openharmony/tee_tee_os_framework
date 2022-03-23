export CONFIG_TA_64BIT := false
export CONFIG_TA_32BIT := true
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_TRNG_ENABLE := true
export CONFIG_OPENSSL_NO_ASM := true
export CONFIG_NO_ZIP_IMAGE := false
export CONFIG_TIMER_FREERUNNING_FIQ_DISABLE := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY := false
export CONFIG_TA_LOCAL_SIGN := true

ifeq ($(CONFIG_APP_TEE_TALOADER), y)
boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
