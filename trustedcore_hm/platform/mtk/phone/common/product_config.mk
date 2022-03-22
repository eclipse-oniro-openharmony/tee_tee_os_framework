export CONFIG_TA_32BIT := true
export MTK_CC_FEATURE  := true
export CONFIG_MTK_TIMER  := true
export CONFIG_MTK_BOOT_INFO := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
export CONFIG_TA_SIGN_KEY_CBG := true
export CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION := true
ifeq ($(CONFIG_GCOV), y)
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
endif

#mtk need libs include:
#aarch64_sys_libs        include (libccmgr libhmdrv_stub libtimer)
#aarch64_arm_kirin_lib   include (libsec_flash_client)
#arm_vendor_ext_libs     include (libdxcc)
#arch64_open_source_libs include (libzlib)

#tee drivers core service
arm_driver_drivers += drv_timer platdrv
vendor_libs += libsec_flash_client
boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

arm_sys_apps += storage tui attestation_ta
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/attestation_ta.elf \
		$(OUTPUTDIR)/arm/apps/storage.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/attestation_ta.elf \
		$(OUTPUTDIR)/aarch64/apps/storage.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
