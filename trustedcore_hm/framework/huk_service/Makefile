# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

# TARGET is an app
TARGET := huk_service${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

huk_service_c_files := $(wildcard src/*.c)

LIBS += huksrv${TARG}

inc-flags += -I$(TOPDIR)/framework/huk_service/include
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif

ifeq ($(CONFIG_HUK_PLAT_COMPATIBLE), true)
flags += -DTEE_HUK_PLAT_COMPATIBLE
endif
