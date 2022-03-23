# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.

# Targets
TARGET := tcmgr_service${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

tcmgr_service_c_files := $(wildcard src/*.c)

LIBS += tcmgrsrv${TARG}

inc-flags += -I$(TOPDIR)/framework/tcmgr_service/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
