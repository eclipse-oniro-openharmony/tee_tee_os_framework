MODULE := libvendor_static$(TARG).a

flags += -Wall -Wextra

libvendor_static_c_files := $(wildcard ../libvendor_shared/src/*.c)
libvendor_static_c_files += $(wildcard $(TOPDIR)/vendor/common/src/*.c)
libvendor_static_c_files += $(wildcard src/efuse/*.c)
libvendor_static_c_files += $(wildcard src/hsm_upgrade/*.c)
libvendor_static_c_files += $(wildcard src/scmi/*.c)
libvendor_static_c_files += $(wildcard src/sec/*.c)
libvendor_static_c_files += $(wildcard src/libhsm_client/src/*.c)

inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/efuse
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/sec/include/

#for hsm_client
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/efuse
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/efuse

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
inc-flags += -DDEF_BUILDUSERMODE
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
