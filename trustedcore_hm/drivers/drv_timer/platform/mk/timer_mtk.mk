# mtk timer driver compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/mtk/include
inc-flags += -I$(SOURCE_DIR)/platform/mtk/hardware
inc-flags += -I$(SOURCE_DIR)/platform/mtk
inc-flags += -I$(SOURCE_DIR)/platform/mtk/rtc

CFILES += platform/mtk/hardware/timer_hw.c

include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/mk/timer_rtc.mk
