#MODULE is a lib

# Targets

MODULE := libteedynsrv${TARG}.a

libteedynsrv_c_files += $(wildcard src/*.c)
inc-flags += -I$(TEELIB)/libteedynsrv/include
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TOPDIR)/prebuild/tee-kernel-local-release/headers/ddk/hmapi/
# Libraries
include $(BUILD_CONFIG)/feature-macro.mk
include $(BUILD_LIB)/lib-common.mk


