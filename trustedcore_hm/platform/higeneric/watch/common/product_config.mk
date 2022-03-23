export CONFIG_TA_32BIT  := true
export HIVCODEC_FEATURE := false
export CONFIG_TIMER_EVENT := true
aarch64_arm_chip_libs += libmspcore librot libweaver libart libbiometric libsec_flash_client libvltmm libchinadrm
arm_chip_libs += libmspcore_a32 librot_a32 libweaver_a32 libart_a32 libbiometric_a32 libsec_flash_client_a32 libvltmm_a32 libchinadrm_a32
ifeq ($(CONFIG_DX_ENABLE), true)
arm_vendor_ext_libs += libdxcc
endif

export CONFIG_TIMER_EVENT := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
export CONFIG_TA_SIGN_KEY_CBG := true
export CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION := true

arm_sys_apps += storage
arm_ext_apps += antiroot kds
arm_chip_apps += secboot

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

ifeq ($(CONFIG_TA_32BIT), true)
product_apps += $(OUTPUTDIR)/arm/drivers/tarunner_a32.elf
endif

ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/storage.elf \
		$(OUTPUTDIR)/arm/apps/antiroot.elf \
		$(OUTPUTDIR)/arm/apps/kds.elf \
		$(OUTPUTDIR)/arm/apps/secboot.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/storage.elf \
		$(OUTPUTDIR)/aarch64/apps/antiroot.elf \
		$(OUTPUTDIR)/aarch64/apps/kds.elf \
		$(OUTPUTDIR)/aarch64/apps/secboot.elf
endif


include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
