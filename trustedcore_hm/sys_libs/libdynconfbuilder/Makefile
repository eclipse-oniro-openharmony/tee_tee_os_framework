# libdynconfbuilder compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

# MODULE
MODULE := libdynconfbuilder${TARG}.a

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

inc-flags += -I$(TOPDIR)/sys_libs/libdynconfbuilder/include
inc-flags += -I$(TOPDIR)/sys_libs/libdynconfmgr/include
inc-flags += -I$(TOPDIR)/../framework/drvmgr/src
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include
inc-flags += -I$(TOPDIR)/lib/teelib/libhmdrv/include
inc-flags += -I$(TOPDIR)/lib/teelib/libteeos/include/tee
inc-flags += -I$(TOPDIR)/lib/teelib/libteeos/include/legacy

# Source files required to build the target
libdynconfbuilder_c_files += $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
