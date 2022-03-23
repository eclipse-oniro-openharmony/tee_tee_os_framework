export CONFIG_TA_64BIT := true
export CONFIG_GTASK_64BIT := true
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GMLIB_IMPORT := false
export CONFIG_TRNG_ENABLE := true
export CONFIG_CLOUD_CA_PUB_KEY := true
export CONFIG_CLOUD_SIGN_PUB_KEY := true
export CONFIG_TA_LOCAL_SIGN := true
export CONFIG_TIMER_FREERUNNING_FIQ_DISABLE := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY := false
export CONFIG_HUK_SERVICE_64BIT := false
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_SSA_64BIT := true
export CONFIG_CRYPTO_SUPPORT_X509 := false
export CONFIG_CRYPTO_ECC_WRAPPER := false
export CONFIG_CRYPTO_AES_WRAPPER := false
#set hisi_drv to BLOCKLIST with no -Werror
BLOCKLIST += trngdriver_lib
export BLOCKLIST

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
