#qemu need libs include:
#aarch64_sys_libs        include (libccmgr libtimer)
#arch64_open_source_libs include (libzlib)
#arm_driver_drivers      include (drv_timer platdrv)
#arm_sys_apps            include (gatekeeper keymaster storage tui attestation_ta)

#tee drivers core service
#export CONFIG_TIMER_EVENT := true
export CONFIG_EXPORT_OPENSSL_SYMBOL := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
