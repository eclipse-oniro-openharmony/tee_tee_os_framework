export CONFIG_TA_32BIT := true
export CONFIG_TA_64BIT := false
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export ENABLE_TA_LOAD_WHITE_BOX_KEY :=true
export CONFIG_GMLIB_IMPORT := false
export CONFIG_DRV_SEC_ENABLE := true
export CONFIG_TRNG_ENABLE := true
export CONFIG_OPENSSL_NO_ASM := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_PERMSRV_64BIT := false

#set hisi_drv to BLOCKLIST with no -Werror
BLOCKLIST += sec/src
export BLOCKLIST

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

product_apps += $(OUTPUTDIR)/arm/drivers/platdrv.elf

arm_sys_apps += storage
product_apps += $(OUTPUTDIR)/arm/apps/storage.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
