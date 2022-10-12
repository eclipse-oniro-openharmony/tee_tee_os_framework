# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

# TARGET is an app
TARGET := huk_service${TARG}.elf

include $(TOPDIR)/mk/var.mk

CFILES := $(wildcard src/*.c)

inc-flags += -I$(SERVICES_PATH)/huk_service/include
inc-flags += -I$(SERVICES_PATH)/huk_service/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TEELIB)/libswcrypto_engine/include/
inc-flags += -I$(TEELIB)/libcrypto_hal/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext/
inc-flags += -I$(TEELIB)/libtee_shared/include/
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(K_SYSLIB)/libsyscalls/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(K_SYSLIB)/libac/include
inc-flags += -I$(K_SYSLIB)/libipc/include
inc-flags += -I$(K_SYSLIB)/libhongmeng/include
inc-flags += -I$(K_SYSLIB)/libhmlog/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libhuk/include
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(TEELIB)/libssa/src

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif

ifeq ($(CONFIG_HUK_PLAT_COMPATIBLE), true)
flags += -DTEE_HUK_PLAT_COMPATIBLE
endif

LDFLAGS += -z noexecstack

include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk
