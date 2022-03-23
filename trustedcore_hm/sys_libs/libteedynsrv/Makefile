#MODULE is a lib

# Targets

MODULE := libteedynsrv${TARG}.a

libteedynsrv_c_files += $(wildcard src/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libteedynsrv/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
# Libraries

include $(TOPDIR)/mk/lib-common.mk


