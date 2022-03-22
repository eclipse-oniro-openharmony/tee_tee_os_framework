MODULE := libvendor_static$(TARG).a

FILES := $(wildcard ../libvendor_shared/src/*.c)
libvendor_static_c_files := $(filter-out ../libvendor_shared/src/se_status.c, $(FILES))
libvendor_static_c_files += $(wildcard ../libvendor_shared/src/driver_api/*.c)
ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT)$(CONFIG_SE_SERVICE_64BIT)),)
libvendor_static_c_files += ../libvendor_shared/src/se_status.c
endif
libvendor_static_c_files += $(wildcard $(TOPDIR)/vendor/common/src/*.c)

inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/vendor/$(PLATFORM_NAME)/libvendor_shared/include
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
inc-flags += -DDEF_BUILDUSERMODE
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
