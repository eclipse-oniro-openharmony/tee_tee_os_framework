#kunpeng need libs include:
#aarch64_sys_libs        include (libccmgr libhmdrv_stub libtimer)
#aarch64_arm_kirin_lib   include (libsec_flash_client)
#arch64_open_source_libs include (libzlib)
#arm_driver_drivers      include (drv_timer platdrv)
#arm_sys_apps            include (gatekeeper keymaster storage tui attestation_ta)

#tee drivers core service
export CONFIG_TIMER_EVENT   := true
aarch64_driver_drivers += drv_timer platdrv
export CONFIG_EXPORT_OPENSSL_SYMBOL := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
export CONFIG_TA_LOCAL_SIGN := true
export CONFIG_PUBKEY_SHAREMEM := true
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
