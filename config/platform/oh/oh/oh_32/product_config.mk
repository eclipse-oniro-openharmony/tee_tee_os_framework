export CONFIG_TA_64BIT := false
export CONFIG_TA_32BIT := true
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_OH32_SEC_ENABLE := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_TA_SIGN_KEY_CBG := true
export CONFIG_PERMSRV_64BIT := false
export ENABLE_CPP := true
export ENABLE_CPP_STATIC := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DRVMGR_64BIT := false
export CONFIG_DYN_CONF := true
export CONFIG_NO_VENDOR_LIB_EMBEDDED := true
export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true

#set drv to BLOCKLIST with no -Werror
BLOCKLIST += ipc/sec
export BLOCKLIST

