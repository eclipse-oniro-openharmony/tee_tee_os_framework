# Target is a TA app
TARGET := vltmm_service.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

vltmm_service_c_files += $(wildcard src/*.c)

c-flags += -DCC_DRIVER -Wall
c-flags += -DSECFLASH_PARTITION_HIGH_HALF_ENABLE
c-flags += -Wno-unused-parameter

# Libraries
LIBS := teeagentcommon_a32 agent_base_a32

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src/
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include/
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/libc_32/hm
c-flags += -I$(PREBUILD_DIR)/headers/ddk/hmapi
c-flags += -I$(PREBUILD_DIR)/headers/ddk/legacy
c-flags += -I$(TOPDIR)/platform/common/tee_config
c-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include
c-flags += -I$(TOPDIR)/vendor/higeneric/libvendor_shared/src/driver_api/
c-flags += -I$(TOPDIR)/drivers/platdrv/include

ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
ifeq ($(chip_type), es)
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore_es
else
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore
endif
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), laguna), )
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/laguna
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), burbank), )
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/burbank
endif

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
