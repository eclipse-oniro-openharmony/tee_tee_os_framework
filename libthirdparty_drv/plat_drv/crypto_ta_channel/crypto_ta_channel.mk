inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_ta_channel
ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DCRYPTO_TA_CHANNEL
CFILES += platform/libthirdparty_drv/plat_drv/crypto_ta_channel/crypto_ta_channel.c
endif #TARGET_BUILD_VARIANT

