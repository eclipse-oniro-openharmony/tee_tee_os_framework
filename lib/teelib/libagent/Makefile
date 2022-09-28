# libagent compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

# Targets
MODULE := libagent${TARG}.a
# Source files required to build the target
CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TEELIB)/libagent/include/
CPPFLAGS += -I$(TEELIB)/libagent_base/include/
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee/
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy/
CPPFLAGS += -Wall

include $(TOPDIR)/mk/lib-common.mk
