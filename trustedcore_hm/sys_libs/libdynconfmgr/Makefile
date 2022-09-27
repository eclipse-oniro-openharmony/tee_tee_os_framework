# libdynconfmgr compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

# MODULE
MODULE := libdynconfmgr${TARG}.a

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

inc-flags += -I$(TOPDIR)/sys_libs/libdynconfmgr/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy

# Source files required to build the target
libdynconfmgr_c_files += $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
