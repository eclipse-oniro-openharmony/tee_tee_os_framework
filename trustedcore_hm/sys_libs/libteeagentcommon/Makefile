#MODULE is a lib

# Targets

MODULE := libteeagentcommon${TARG}.a

libteeagentcommon_c_files += $(wildcard src/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src

# Libraries

include $(TOPDIR)/mk/lib-common.mk


