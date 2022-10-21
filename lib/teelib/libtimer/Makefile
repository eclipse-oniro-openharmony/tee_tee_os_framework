#
# Copyright 2022, Huawei Co. Ltd
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libtimer${TARG}.a

flags += -fno-builtin

inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libagent/include
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(PREBUILD_DIR)/headers/sys/timemgr
ifeq (${TARG}, _a32)
inc-flags += -I$(TEELIB)/libtimer/include/arm
else
inc-flags += -I$(TEELIB)/libtimer/include/aarch64
endif

# Source files required to build the target
ifeq ($(CONFIG_OFF_DRV_TIMER), y)
libtimer_c_files := $(wildcard src/*.c)
libtimer_c_files += $(wildcard src/*/*.c)
endif

include $(BUILD_LIB)/lib-common.mk
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
