# Target is a TA app
TARGET := rpmb_key.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

rpmb_key_c_files += $(wildcard src/*.c)

# Libraries
LIBS :=

inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_hsm/src/
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_common_client/src
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libscmi/include
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/hm/TEE
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/gpapi
inc-flags += -I$(TOPDIR)/apps/include

include $(TOPDIR)/mk/ta-common.mk
