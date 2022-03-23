# CT timer driver compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.

SOURCE_DIR := $(TOPDIR)/drivers/drv_timer

inc-flags += -I$(SOURCE_DIR)/platform/ct/include
inc-flags += -I$(SOURCE_DIR)/platform/ct/hardware
inc-flags += -I$(SOURCE_DIR)/platform/ct

CFILES += platform/ct/hardware/timer_hw.c
