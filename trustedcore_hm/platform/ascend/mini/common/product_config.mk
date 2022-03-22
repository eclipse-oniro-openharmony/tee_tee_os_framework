#mini need libs include:
#aarch64_sys_libs        include (libccmgr libhmdrv_stub libtimer)
#aarch64_arm_kirin_lib   include (libsec_flash_client)
#arch64_open_source_libs include (libzlib)
#arm_driver_drivers      include (drv_timer platdrv)
#arm_sys_apps            include (gatekeeper keymaster storage tui attestation_ta)
export CONFIG_TIMER_EVENT := true
export CONFIG_KMS := false
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true

aarch64_apps += hsm hsm_bbox firmware_upgrade hsm_efuse hsm_flash
aarch64_inner_ext_libs += libcmscbb

product_apps += $(OUTPUTDIR)/aarch64/apps/hsm.elf
product_apps += $(OUTPUTDIR)/aarch64/apps/hsm_bbox.elf
product_apps += $(OUTPUTDIR)/aarch64/apps/firmware_upgrade.elf
product_apps += $(OUTPUTDIR)/aarch64/apps/hsm_efuse.elf
product_apps += $(OUTPUTDIR)/aarch64/apps/hsm_flash.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
