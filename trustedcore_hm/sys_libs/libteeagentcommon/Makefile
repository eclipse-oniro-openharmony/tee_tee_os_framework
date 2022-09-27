#MODULE is a lib

# Targets

MODULE := libteeagentcommon${TARG}.a

libteeagentcommon_c_files += $(wildcard src/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src
inc-flags += -I$(TOPDIR)/lib/teelib/libteeos/include/tee
inc-flags += -I$(TOPDIR)/lib/teelib/libteeos/include/legacy

# Libraries

include $(TOPDIR)/mk/lib-common.mk


