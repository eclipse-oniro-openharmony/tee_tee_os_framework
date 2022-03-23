# Target is a TA app
TARGET := firmware_upgrade.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

firmware_upgrade_c_files += $(wildcard $(TOPDIR)/apps/firmware_upgrade/src/*.c)

# Libraries
LIBS :=

inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_hsm/src/
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_common_client/src
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/hm/TEE
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/efuse
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/hsm_upgrade
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/scmi
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/sec
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/apps/include

include $(TOPDIR)/mk/ta-common.mk

