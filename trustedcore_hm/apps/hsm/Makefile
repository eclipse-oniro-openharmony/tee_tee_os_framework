# Target is a TA app
TARGET := hsm.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

hsm_c_files += $(wildcard src/*.c)

flags += -DCC_DRIVER -Wall
flags += -DSECFLASH_PARTITION_HIGH_HALF_ENABLE

# Libraries
LIBS := teeagentcommon teeagentcommon_client

inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src/
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_common_client/src
inc-flags += -I$(TOPDIR)/sys_libs/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libhsm_client/src
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/efuse
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/hsm_upgrade
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/scmi
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/sec
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/apps/hsm/include

include $(TOPDIR)/mk/ta-common.mk

INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
