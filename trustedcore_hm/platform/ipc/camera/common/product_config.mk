#tee drivers core service

export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true
export CONFIG_LIBFUZZER_SERVICE_64BIT :=false

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
