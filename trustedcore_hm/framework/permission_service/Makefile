# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# TARGET is an app
TARGET := permission_service${TARG}.elf

include $(TOPDIR)/mk/var.mk

permission_service_c_files :=  $(wildcard src/*.c)

LIBS += permsrv${TARG}

# these libs are for elf verify
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}       \
    dynconfmgr${TARG}     \
    dynconfbuilder${TARG}

LIBS += base_shared${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/drivers/base_mgr/tee_misc_driver/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
c-flags += -I$(TOPDIR)/framework/permission_service/src

permission_service_c_files += $(wildcard src/auth/tee_auth_sign_rsa.c)
c-flags += -I$(TOPDIR)/framework/permission_service/src/auth/tee_auth_sign_rsa.h

include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif
