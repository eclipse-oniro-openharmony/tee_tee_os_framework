# libagent compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

# Targets
MODULE := libagent${TARG}.a
# Source files required to build the target
CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TOPDIR)/lib/teelib/libagent/include/
CPPFLAGS += -I$(TOPDIR)/lib/teelib/libagent_base/include/
CPPFLAGS += -I$(TOPDIR)/lib/teelib/libteeos/include/tee/
CPPFLAGS += -I$(TOPDIR)/lib/teelib/libteeos/include/legacy/
CPPFLAGS += -Wall

include $(TOPDIR)/mk/lib-common.mk
