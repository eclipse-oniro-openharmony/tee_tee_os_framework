export CONFIG_TA_32BIT := true
export CONFIG_TA_64BIT := false
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_IPC_SEC_ENABLE := true
export CONFIG_TRNG_ENABLE := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_TA_SIGN_KEY_CBG := true
export CONFIG_SE_SERVICE_32BIT :=true
export CONFIG_NO_ZIP_IMAGE := true
export CONFIG_PERMSRV_64BIT := false

#set hisi_drv to BLOCKLIST with no -Werror
BLOCKLIST += ipc/sec
export BLOCKLIST

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

product_apps += $(OUTPUTDIR)/arm/drivers/platdrv.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
