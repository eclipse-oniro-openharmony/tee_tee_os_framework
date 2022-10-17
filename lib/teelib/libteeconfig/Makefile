# MODULE is a lib
# Targets

MODULE := libteeconfig$(TARG).a

flags += -fno-builtin

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_SUPPORT_GET_DIEID), true)
flags += -DCONFIG_SUPPORT_GET_DIEID
endif

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

ifneq (, $(filter $(TARGET_BOARD_PLATFORM), baltimore))
flags += -DCONFIG_GENERIC_ROT
flags += -DCONFIG_GENERIC_ART
endif
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext
inc-flags += -I$(TEELIB)/libteeconfig/include/kernel/
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libagent_base/include
inc-flags += -I$(TEELIB)/libhmdrv/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src
inc-flags += -I$(TEELIB)/libteemem/include

# Source files required to build the target
libteeconfig_c_files += $(wildcard src/drv_hal/*.c)
libteeconfig_c_files += $(wildcard src/tee_config/*.c)
ifeq ($(CONFIG_TEST_CA_CHECK), y)
    libteeconfig_c_files += src/tee_test_config/tee_test_calist.c
endif

ifeq ($(CONFIG_HISI_MSPC_IPC_TEST), true)
c-flags += -DCONFIG_HISI_MSPC_IPC_TEST
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
flags += -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
