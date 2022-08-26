# teesmcmgr compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

# Targets
TARGET := teesmcmgr.elf

TA_NAME := teesmcmgr

include $(TOPDIR)/mk/var.mk

PWD := $(shell pwd)

flags += -I$(PWD)/include
flags += -I$(PREBUILD_SYS)/mmgr_sysmgr
flags += -I$(PREBUILD_SYS)/irqmgr

LDFLAGS += -u _hm_start -z noexecstack

# Source files required to build the target
teesmcmgr_c_files :=  $(wildcard src/*.c)

$(BUILD_DIR)/$(TA_NAME): $(BUILD_DIR)/$(TARGETS)
	cp $< $@

# Libraries
LIBS := c_shared$(TARG)
LDFLAGS += --dynamic-linker=libc_shared$(TARG).so
ENTRY_POINT := _hm_start

include $(TOPDIR)/mk/svc-common.mk

flags += -fvisibility=default
