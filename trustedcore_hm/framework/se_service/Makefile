# Copyright Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.

# TARGET is an app
TARGET := se_service${TARG}.elf

include $(TOPDIR)/mk/var.mk

se_service_c_files := $(wildcard src/*.c)

LIBS += sesrv${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif
