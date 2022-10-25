# libhmdrv compile flags.
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.

# Targets
MODULE := libhmdrv${TARG}.a

CPPFLAGS += -I$(TEELIB)/libhmdrv/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteemem/include

# Source files required to build the target
CFILES := $(wildcard src/*.c)

include $(BUILD_LIB)/lib-common.mk
