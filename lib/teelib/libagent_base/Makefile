# libagent_base compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

# Targets
MODULE := libagent_base${TARG}.a

# source files required to build the target
CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TEELIB)/libagent_base/include/
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include

include $(TOPDIR)/mk/lib-common.mk
