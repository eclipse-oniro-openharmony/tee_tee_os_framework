# Copyright (c) Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/higeneric/include
inc-flags += -I$(SOURCE_DIR)/platform/higeneric/hardware
inc-flags += -I$(SOURCE_DIR)/platform/higeneric/rtc
inc-flags += -I$(SOURCE_DIR)/platform/higeneric

CFILES += platform/higeneric/hardware/timer_hw.c
CFILES += platform/higeneric/rtc/timer_rtc.c
