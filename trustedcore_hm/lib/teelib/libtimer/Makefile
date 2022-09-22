#
# Copyright 2022, Huawei Co. Ltd
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libtimer${TARG}.a

flags += -fno-builtin

inc-flags += -I$(TOPDIR)/lib/teelib/libtimer/include
inc-flags += -I$(PREBUILD_DIR)/headers/sys/timemgr
ifeq (${TARG}, _a32)
inc-flags += -I$(TOPDIR)/lib/teelib/libtimer/include/arm
else
inc-flags += -I$(TOPDIR)/lib/teelib/libtimer/include/aarch64
endif

ifeq ($(chip_type), es)
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es
else
ifeq ($(chip_type), cs2)
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_cs2
else
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
endif
endif

# Source files required to build the target
ifeq ($(CONFIG_OFF_DRV_TIMER), y)
libtimer_c_files := $(wildcard src/*.c)
libtimer_c_files += $(wildcard src/*/*.c)
endif

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
ifeq (${TARG}, _a32)
EXPORT_HDRS += $(wildcard include/arm/*.h)
else
EXPORT_HDRS += $(wildcard include/aarch64/*.h)
endif

include $(TOPDIR)/mk/lib-common.mk
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
