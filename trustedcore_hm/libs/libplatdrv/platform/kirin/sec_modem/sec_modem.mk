

SECURE_OS_DIR := $(TOPDIR)

LOCAL_HEADER   := $(SECURE_OS_DIR)/prebuild/hm-teeos-release/headers
LOCAL_LIBC_INC := $(LOCAL_HEADER)/libc_32
LOCAL_HM_INC   := $(LOCAL_HEADER)/hm_32
LOCAL_KERNEL_INC := $(LOCAL_HEADER)/kernel
LOCAL_TOOLCHAINS := $(SECURE_OS_DIR)/prebuild/toolchains
override MODEM_TOP_DIR := $(CURDIR)/../../../../../../../../../hisi/modem/drv/teeos
override BALONG_TOPDIR := $(CURDIR)/../../../../../../../../../hisi

inc-flags += -I$(LOCAL_KERNEL_INC)
inc-flags += -I$(LOCAL_KERNEL_INC)/uapi
inc-flags += -I$(LOCAL_KERNEL_INC)/arch/arm/uapi
inc-flags += -I$(LOCAL_KERNEL_INC)/kirin
inc-flags += -I$(LOCAL_LIBC_INC)
inc-flags += -I$(LOCAL_LIBC_INC)/arch/generic
inc-flags += -I$(LOCAL_LIBC_INC)/arch/$(ARCH)
inc-flags += -I$(LOCAL_LIBC_INC)/hm
inc-flags += -I$(LOCAL_HM_INC)
inc-flags += -I$(LOCAL_HEADER)/hm
inc-flags += -I$(LOCAL_HM_INC)/kernel
inc-flags += -I$(SECURE_OS_DIR)/sys_libs/libteeconfig/include/TEE_ext
inc-flags += -I$(SECURE_OS_DIR)/sys_libs/libteeconfig/include/kernel
inc-flags += -I$(SECURE_OS_DIR)/sys_libs/libhmdrv_stub/include
ifeq ($(CONFIG_DX_ENABLE), true)
inc-flags += -I$(SECURE_OS_DIR)/thirdparty/vendor/libdxcc/pal/include/
inc-flags += -I$(SECURE_OS_DIR)/thirdparty/vendor/libdxcc/austin/shared/include/crys
inc-flags += -I$(SECURE_OS_DIR)/thirdparty/vendor/libdxcc/austin/shared/include/pal
endif
inc-flags += -I$(SECURE_OS_DIR)/libs/libplatdrv/platform/kirin/secureboot
inc-flags += -I$(SECURE_OS_DIR)/libs/libplatdrv/platform/kirin/secureboot/bspatch
inc-flags += -I$(SECURE_OS_DIR)/drivers/platdrv/include
inc-flags += -I$(SECURE_OS_DIR)/drivers/include
inc-flags += -I$(SECURE_OS_DIR)/sys_libs/libccmgr/include

inc-flags += -I$(SECURE_OS_DIR)/libs/libplatdrv/platform/kirin/secureboot
inc-flags += -DCONFIG_MODEM_PLATDRV_64BIT_BBIT

ifeq ($(chip_type),es2)
inc-flags      += -I$(SECURE_OS_DIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es2
else
ifeq ($(chip_type),es)
inc-flags      += -I$(SECURE_OS_DIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es
else
inc-flags      += -I$(SECURE_OS_DIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
endif
endif

include $(SECURE_OS_DIR)/libs/libplatdrv/platform/kirin/sec_modem/teeos/modem_build.mk
