# libdynconfmgr compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

# MODULE
MODULE := libdynconfmgr${TARG}.a

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

inc-flags += -I$(SYSLIB)/libdynconfmgr/include
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteemem/include

# Source files required to build the target
libdynconfmgr_c_files += $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
