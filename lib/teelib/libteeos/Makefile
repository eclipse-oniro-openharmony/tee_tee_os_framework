#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libteeos${TARG}.a

# This library only provides 32-bit headers of libbteeos.
# If we want 64-bit headers of libteeos, we should depend on libac temporarily.

CPPFLAGS += -I$(TEELIB)/libhmdrv/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libagent_base/include # tee_secfile_load_agent.h
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/include # root_status_ops.h
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel/
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext/
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libtee_shared/include # oemkey.h
CPPFLAGS += -I$(TOPDIR)/drivers/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/mmgr
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/mmgr_sysmgr
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/ssa
CPPFLAGS += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/sys/huk
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee

# Source files required to build the target
ASMFILES := $(wildcard src/*.S)
ifeq (${TARG}, _a32)
ASMFILES += $(wildcard src/*/*.S)
ASMFILES += $(wildcard src/*/arm/*.S)
endif

CFILES   := $(wildcard src/*.c)
CFILES   += $(wildcard src/*/*.c)

ifneq ($(CONFIG_PRIVATE_OEMKEY_SUPPORT),y)
CFILES := $(filter-out src/tee_private_api.c, $(CFILES))
endif

# fixup for TEE, check "trustedcore/trustedcore_plats.mk"
CFLAGS +=	-DARM_PAE=1 \
		-D__ARM_ARCH__=7
CFLAGS +=	-DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

include $(TOPDIR)/mk/lib-common.mk
