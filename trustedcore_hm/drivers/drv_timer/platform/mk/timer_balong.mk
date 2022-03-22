# balong timer driver compile rule. for all kirin product
# Copyright (c) Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.
SOURCE_DIR := $(TOPDIR)/drivers/drv_timer
inc-flags += -I$(TOPDIR)/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/include
inc-flags += -I$(SOURCE_DIR)/platform/balong/include
inc-flags += -I$(SOURCE_DIR)/platform/balong/hardware
inc-flags += -I$(SOURCE_DIR)/platform/balong/rtc
inc-flags += -I$(SOURCE_DIR)/platform/balong

CFILES += platform/balong/hardware/timer_hw.c
CFILES += platform/balong/rtc/timer_rtc.c
