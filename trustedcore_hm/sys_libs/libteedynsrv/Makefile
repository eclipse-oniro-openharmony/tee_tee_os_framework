#MODULE is a lib

# Targets

MODULE := libteedynsrv${TARG}.a

libteedynsrv_c_files += $(wildcard src/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libteedynsrv/include
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/ddk/hmapi/
# Libraries
include $(TOPDIR)/mk/feature-macro.mk
include $(TOPDIR)/mk/lib-common.mk


