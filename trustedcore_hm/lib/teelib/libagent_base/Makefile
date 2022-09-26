# libagent_base compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

# Targets
MODULE := libagent_base${TARG}.a

# source files required to build the target
CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TOPDIR)/lib/teelib/libagent_base/include/
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

include $(TOPDIR)/mk/lib-common.mk
