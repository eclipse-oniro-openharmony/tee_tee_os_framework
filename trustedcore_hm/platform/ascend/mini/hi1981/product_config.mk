export CONFIG_TA_64BIT := true
export CONFIG_GTASK_64BIT := true
export CONFIG_MTK_TIMER := false
export CONFIG_PLATDRV_64BIT := true
export CONFIG_DRV_TIMER_64BIT := true

#false=32 true=64 nothing=32&64 ALL
export CONFIG_SUPPORT_64BIT := true

export CONFIG_HSM := true
export CONFIG_RESUME_FREE_TIMER := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_TRNG_ENABLE := true
#export CONFIG_ASCEND_SEC_ENABLE := true
export CONFIG_HUK_SERVICE_64BIT := true
export CONFIG_PERMSRV_64BIT := true
export ENABLE_TA_LOAD_WHITE_BOX_KEY := true

#set hisi_drv to BLOCKLIST with no -Werror
BLOCKLIST += libcmscbb libhsm_client sec_hal sec/api sfc hsm firmware_upgrade
export BLOCKLIST

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
