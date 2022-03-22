export CONFIG_TA_64BIT := false
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_RPMB_64BIT := false
export CONFIG_ATTESTATION_TA := true
export CONFIG_GATEKEEPER_32BIT := true
export CONFIG_KEYMASTER_32BIT := true
export CONFIG_PERMSRV_64BIT := false
export CONFIG_PLATDRV_64BIT := false
export CONFIG_TIMER_EVENT := true
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export CONFIG_TIMER_FREERUNNING_FIQ_DISABLE := true
export CONFIG_GMLIB_IMPORT := true
export CONFIG_DX_ENABLE := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_SE_SERVICE_32BIT :=true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_SOFT_RTC_TICK := false

#set hisi_drv to BLOCKLIST with no -Werror
BLOCKLIST += spi fingerprint touchscreen eSE
export BLOCKLIST

arm_chip_apps +=
arm_ext_apps := kds
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/kds.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/kds.elf
endif

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
