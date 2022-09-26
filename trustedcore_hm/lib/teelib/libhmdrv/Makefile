# libhmdrv compile flags.
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.

# Targets
MODULE := libhmdrv${TARG}.a

CPPFLAGS += -I$(TOPDIR)/lib/teelib/libhmdrv/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/include

# Source files required to build the target
CFILES := $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
