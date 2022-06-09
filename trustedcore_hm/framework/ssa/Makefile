# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

DRIVER := ssa${TARG}.elf

include $(TOPDIR)/mk/var.mk

ssa_c_files += $(wildcard src/*.c)
ifneq ($(CONFIG_TEE_FS_OPER),y)
ssa_c_files := $(filter-out src/tee_fs_oper_config.c, $(ssa_c_files))
flags += -DTEE_FS_OPER
endif

ifeq ($(CONFIG_MERGE_HUK_SSA),y)
ssa_c_files += $(TOPDIR)/framework/huk_service/src/huk_service_config.c
endif

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
ifeq ($(CONFIG_MERGE_HUK_SSA),y)
inc-flags += -I$(TOPDIR)/framework/huk_service/include
endif
# Libraries
LIBS := ssagent${TARG}

ifeq ($(CONFIG_DYNLINK),y)
DRV_LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk
