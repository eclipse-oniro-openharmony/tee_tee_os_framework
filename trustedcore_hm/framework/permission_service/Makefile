# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# TARGET is an app
TARGET := permission_service${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

permission_service_c_files :=  $(wildcard src/*.c)

LIBS += permsrv${TARG}

# these libs are for elf verify
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}       \
    dynconfmgr${TARG}     \
    dynconfbuilder${TARG}

ifeq ($(CONFIG_TA_CMS_SIGNATURE),y)
ifeq (${TARG}, )
LIBS += cmscbb tee_cmscbb${TARG}
endif
endif

LIBS += base_shared${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
c-flags += -I$(TOPDIR)/framework/permission_service/src

include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
