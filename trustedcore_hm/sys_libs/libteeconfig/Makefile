# MODULE is a lib
# Targets

MODULE := libteeconfig$(TARG).a

flags += -fno-builtin

ifneq (, $(filter $(TARGET_BOARD_PLATFORM), kirin990))
flags += -DCONFIG_HISI_SECFLASH
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifneq (, $(filter $(TARGET_BOARD_PLATFORM), baltimore))
flags += -DCONFIG_GENERIC_ROT
flags += -DHISI_MSP_SECFLASH
flags += -DCONFIG_GENERIC_ART
endif
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
ifeq ($(chip_type), es)
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/$(TARGET_BOARD_PLATFORM)_es/
else ifeq ($(chip_type), cs2)
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/$(TARGET_BOARD_PLATFORM)_cs2/
else
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/$(TARGET_BOARD_PLATFORM)/
endif

# Source files required to build the target
libteeconfig_c_files += $(wildcard src/*.c)
libteeconfig_c_files += $(PLATFORM_DIR)/common/tee_config/teeos_config.c
libteeconfig_c_files += $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config/product_config.c

EXPORT_HDRS += $(wildcard include/*)
EXPORT_HDRS += $(wildcard include/*/*.h)

ifeq ($(CONFIG_HSM), true)
flags += -DTEE_SUPPORT_HSM
endif

ifeq ($(CONFIG_HISI_MSPC_IPC_TEST), true)
c-flags += -DCONFIG_HISI_MSPC_IPC_TEST
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

flags += -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
