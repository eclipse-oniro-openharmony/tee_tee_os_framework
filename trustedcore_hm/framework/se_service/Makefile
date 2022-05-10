# Copyright Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.

# TARGET is an app
TARGET := se_service${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

se_service_c_files := $(wildcard src/*.c)

LIBS += sesrv${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
