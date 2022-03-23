# platform compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

export CONFIG_TA_32BIT  := true
export CONFIG_TIMER_EVENT := true
export CONFIG_TA_SIGN_KEY_CBG := true

aarch64_arm_chip_libs += libmspcore librot libweaver libart libbiometric libsec_flash_client libvltmm libchinadrm
arm_chip_libs += libmspcore_a32 librot_a32 libweaver_a32 libart_a32 libbiometric_a32 libsec_flash_client_a32 libvltmm_a32 libchinadrm_a32
ifeq ($(CONFIG_DX_ENABLE), true)
arm_vendor_ext_libs += libdxcc
endif

#tee drivers core service
arm_sys_apps += storage attestation_ta
arm_ext_apps += kds
arm_chip_apps += secboot
ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore denver laguna), )
ifneq ($(WITH_MODEM), false)
arm_chip_libs += libsec_modem
endif
endif

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

export CONFIG_CRYPTO_SUPPORT_EC25519 := true
export CONFIG_CRYPTO_SUPPORT_X509 := true
export CONFIG_CRYPTO_ECC_WRAPPER := true
export CONFIG_CRYPTO_AES_WRAPPER := true

ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/attestation_ta.elf \
		$(OUTPUTDIR)/arm/apps/storage.elf \
		$(OUTPUTDIR)/arm/apps/secboot.elf \
		$(OUTPUTDIR)/arm/apps/kds.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/attestation_ta.elf \
		$(OUTPUTDIR)/aarch64/apps/storage.elf \
		$(OUTPUTDIR)/aarch64/apps/secboot.elf \
		$(OUTPUTDIR)/aarch64/apps/kds.elf
endif


include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/modules.mk
