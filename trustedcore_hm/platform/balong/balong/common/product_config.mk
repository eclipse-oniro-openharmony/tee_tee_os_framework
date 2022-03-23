#balong need libs include:
export CONFIG_TA_32BIT  := true
export CONFIG_TIMER_EVENT := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
ifeq ($(CONFIG_DX_ENABLE), true)
arm_vendor_ext_libs += libdxcc
endif

ifeq ($(CONFIG_DRV_64BIT),false)
endif
ifeq ($(CONFIG_DRV_64BIT),true)
endif


include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
