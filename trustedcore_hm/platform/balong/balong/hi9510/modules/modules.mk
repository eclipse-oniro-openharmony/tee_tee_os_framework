# hi9500 modules compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
ifneq ($(findstring true, $(CONFIG_TUI_64BIT)$(CONFIG_TUI_32BIT)),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/modules/tui.mk
endif
