
#aarch64_sys_libs        include (libccmgr libhmdrv_stub libtimer)
#aarch64_arm_kirin_lib   include (libsec_flash_client)
#arch64_open_source_libs include (libzlib)
#arm_driver_drivers      include (drv_timer platdrv)

export CONFIG_TA_32BIT  := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
export CONFIG_TIMER_EVENT := true
ifeq ($(CONFIG_DX_ENABLE), true)
arm_vendor_ext_libs += libdxcc
endif

#tee drivers core service
arm_sys_apps +=
arm_ext_apps +=
arm_chip_apps +=

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk

