# platform compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
#
ifneq ($(strip $(TARGET_BOARD_PLATFORM)), )

TRUSTEDCORE_CHIP_CHOOSE     := 0
TRUSTEDCORE_PLATFORM_CHOOSE := 0

include $(PLATFORM_DIR)/../mk/plat/$(TARGET_BOARD_PLATFORM)/plat.mk

# if chip.mk exist, include chip.mk
ifeq ($(strip $(PRODUCT_NAME)), )
ifneq ($(wildcard $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(CHIP_NAME)/chip.mk),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(CHIP_NAME)/chip.mk
endif
ifneq ($(wildcard $(PLATFORM_DIR)/$(PLATFORM_NAME)/common/chip.mk),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/common/chip.mk
endif
else
ifneq ($(wildcard $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/chip.mk),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/chip.mk
endif
ifneq ($(wildcard $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/chip.mk),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/chip.mk
endif
endif

TRUSTEDCORE_PLATFORM_FLAGS += \
    -DTRUSTEDCORE_CHIP_CHOOSE=$(TRUSTEDCORE_CHIP_CHOOSE) \
    -DTRUSTEDCORE_PLATFORM_CHOOSE=$(TRUSTEDCORE_PLATFORM_CHOOSE)
endif
