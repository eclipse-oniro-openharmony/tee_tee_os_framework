# libspawn_common compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

MODULE := libspawn_common$(TARG).a

inc-flags += -I$(SYSLIB)/libspawn_common/include
inc-flags += -I$(TEELIB)/libteeos/include/tee

# Source files required to build the target
libspawn_common_c_files += $(wildcard src/*.c)

include $(BUILD_LIB)/lib-common.mk
