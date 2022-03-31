# tui compile rule, modified by t00292236
# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

DRIVER := tui${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

tui_c_files += $(wildcard src/*.c)

# Libraries
LIBS := tui_internal${TARG}

inc-flags += -I$(TOPDIR)/libs/libthp_common/include

ifeq ($(CONFIG_DYNLINK),y)
DRV_LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk

