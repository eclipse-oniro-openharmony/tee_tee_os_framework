#
# Copyright 2022, Huawei Co. Ltd
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libtimer${TARG}.a

flags += -fno-builtin

inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include
inc-flags += -I$(TOPDIR)/drivers/drv_timer/src
inc-flags += -I$(TOPDIR)/drivers/drv_timer/platform/$(PLATFORM_NAME)/include/
inc-flags += -I$(TOPDIR)/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/timer/include
inc-flags += -I$(PREBUILD_DIR)/headers/sys/timemgr
ifeq (${TARG}, _a32)
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include/arm
else
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include/aarch64
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
ifeq ($(CONFIG_TIMER_DISABLE), y)
libtimer_c_files := src/tee_timer_stub.c
libtimer_c_files += src/tee_time_rtc.c
else ifeq ($(CONFIG_OFF_DRV_TIMER), y)
libtimer_c_files := $(wildcard src/*.c)
libtimer_c_files += $(wildcard src/*/*.c)
libtimer_c_files := $(filter-out src/tee_timer_stub.c, $(libtimer_c_files))
libtimer_c_files := $(filter-out src/timer_adapt/tee_sec_timer_adapt.c, $(libtimer_c_files))
libtimer_c_files := $(filter-out src/tee_timer_call.c, $(libtimer_c_files))
libtimer_c_files := $(filter-out src/rtc_adapt/rtc_drv_timer_adapt.c, $(libtimer_c_files))
ifneq ($(CONFIG_RTC_TIMER), y)
libtimer_c_files := $(filter-out src/rtc_adapt/rtc_drv_rtc_adapt.c, $(libtimer_c_files))
endif
else
libtimer_c_files := $(wildcard src/*.c)
libtimer_c_files += $(wildcard src/*/*.c)
libtimer_c_files := $(filter-out src/tee_timer_stub.c, $(libtimer_c_files))
libtimer_c_files := $(filter-out src/timer_adapt/tee_generic_timer_adapt.c, $(libtimer_c_files))
libtimer_c_files := $(filter-out src/rtc_adapt/rtc_drv_rtc_adapt.c, $(libtimer_c_files))
ifneq ($(CONFIG_RTC_TIMER), y)
libtimer_c_files := $(filter-out src/rtc_adapt/rtc_drv_timer_adapt.c, $(libtimer_c_files))
endif
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
