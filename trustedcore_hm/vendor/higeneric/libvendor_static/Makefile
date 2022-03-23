MODULE := libvendor_static$(TARG).a

FILES := $(wildcard ../libvendor_shared/src/*.c)
libvendor_static_c_files := $(filter-out ../libvendor_shared/src/se_status.c ../libvendor_shared/src/hisi_mspc.c ../libvendor_shared/src/hisi_mspc_stubs.c, $(FILES))
libvendor_static_c_files += $(wildcard ../libvendor_shared/src/driver_api/*.c)
ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT)$(CONFIG_SE_SERVICE_64BIT)),)
libvendor_static_c_files += ../libvendor_shared/src/se_status.c
endif
libvendor_static_c_files += $(wildcard $(TOPDIR)/vendor/common/src/*.c)
libvendor_shared_c_files += $(wildcard $(TOPDIR)/libs/libsec_flash_client/src/*.c)

inc-flags += -I$(TOPDIR)/libs/libvltmm_a32/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/libs/libsec_flash_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
inc-flags += -DDEF_BUILDUSERMODE
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
libvendor_static_c_files += ../libvendor_shared/src/hisi_mspc.c
else
libvendor_static_c_files += ../libvendor_shared/src/hisi_mspc_stubs.c
endif

ifeq ($(CONFIG_HISI_MSPC_IPC_TEST), true)
flags += -DCONFIG_HISI_MSPC_IPC_TEST
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
