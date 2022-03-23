#
# Copyright 2017, Huawei Co. Ltd
#
# See "HUAWEI_LICENSE" for details.
#

# Targets

MODULE := libtimer${TARG}.a

flags += -fno-builtin

inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(TOPDIR)/drivers/platdrv/include/
inc-flags += -I$(TOPDIR)/drivers/drv_timer/src
inc-flags += -I$(TOPDIR)/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/include
inc-flags += -I$(TOPDIR)/drivers/drv_timer/platform/$(PLATFORM_NAME)/include/
ifeq ($(chip_type), es)
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es
else
ifeq ($(chip_type), cs2)
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_cs2
else
inc-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
endif
endif

ifeq (${TARG}, _a32)
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include/arm
else
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include/aarch64
endif

ifeq ($(CONFIG_GENERIC_TIMER), y)
flags += -DCONFIG_GENERIC_TIMER
endif
inc-flags += -I$(PREBUILD_DIR)/headers/sys/timemgr
inc-flags += -I$(PREBUILD_DIR)/headers/include/uapi

# Source files required to build the target
libtimer_c_files += $(wildcard src/*.c)

ifneq ($(CONFIG_LIB_TIMEMGR),y)
libtimer_c_files := $(filter-out  src/classic_timer_api.c, $(libtimer_c_files))
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
