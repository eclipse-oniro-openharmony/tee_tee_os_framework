# hi6932 product config
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
export CONFIG_TA_64BIT := false
export CONFIG_TA_32BIT := true
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
export CONFIG_HISI_TIMER := true
export CONFIG_PLATDRV_64BIT := false
export CONFIG_DRV_TIMER_64BIT := false
export CONFIG_DRV_64BIT := false
export ENABLE_TA_LOAD_WHITE_BOX_KEY :=true
export CONFIG_GMLIB_IMPORT := false
export CONFIG_DX_ENABLE := true
export CONFIG_OPENSSL_NO_ASM := true
export CONFIG_HUK_SERVICE_64BIT := false
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_HUK_PLAT_COMPATIBLE := true
export CONFIG_NO_ZIP_IMAGE := false
export CONFIG_ARM32_FLUSH_CACHE := true
export CONFIG_PERMSRV_64BIT := false

BLOCKLIST += ccdriver_lib libdxcc cc_driver
export BLOCKLIST

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/modules.mk
