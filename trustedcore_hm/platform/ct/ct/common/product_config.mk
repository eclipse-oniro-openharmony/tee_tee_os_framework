export CONFIG_TIMER_EVENT   := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true

aarch64_inner_ext_libs += libcmscbb

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
