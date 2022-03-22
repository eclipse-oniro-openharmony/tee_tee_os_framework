# Target is a TA app
TARGET := hsm_flash.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

hsm_flash_c_files += $(wildcard src/*.c)

inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_hsm/src/
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_common_client/src
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libscmi/include
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/hm/TEE
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/gpapi
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/hsm_upgrade
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/sfc
inc-flags += -I$(TOPDIR)/apps/include

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(equip_name),  mdc_equip)
flags += -DMDC_HSM_EQUIP
endif
