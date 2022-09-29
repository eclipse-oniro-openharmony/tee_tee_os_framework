#MODULE is a lib

# Targets

MODULE := libteeagentcommon${TARG}.a

libteeagentcommon_c_files += $(wildcard src/*.c)
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy

# Libraries

include $(TOPDIR)/mk/lib-common.mk


