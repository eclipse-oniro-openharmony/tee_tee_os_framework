
MODULE := libccmgr${TARG}.a

flags += -fno-builtin

ifeq ($(MTK_CC_FEATURE), true)
inc-flags += -DSUPPORT_M_CC
endif

inc-flags += -I$(TOPDIR)/sys_libs/libccmgr/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include

# Source files required to build the target
libccmgr_c_files += $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libccmgr/include/*)

include $(TOPDIR)/mk/lib-common.mk
