# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

DRIVER := ssa${TARG}.elf

include $(TOPDIR)/mk/var.mk

# Libraries
LIBS := ssagent${TARG}

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk
