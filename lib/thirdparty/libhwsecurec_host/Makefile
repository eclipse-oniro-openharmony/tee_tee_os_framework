#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libhwsecurec_host.a
TARGET_IS_HOST = y

ifeq ($(USE_LIBC_32), y)
	ARCH = arm
endif
ifeq ($(USE_LIBC_64), y)
	ARCH = aarch64
endif

ifeq ($(TARGET_IS_ARM32),y)
	ARCH = arm
endif

TOPDIR = $(CURDIR)/../../..
ifeq ($(PLATFORM_DIR),)
	PLATFORM_DIR = $(OLD_TOPDIR)/platform
endif

ifneq ($(O),)
OUTPUTDIR := $(O)
else
OUTPUTDIR := $(TOPDIR)/output
endif

ifeq ($(HM_SDK_VER),)
HM_SDK_VER := tee-kernel-release
endif

include $(BUILD_CONFIG)/var.mk

# Source files required to build the target
CFILES := $(wildcard $(TEE_SECUREC_DIR)/src/*.c)
libhwsecurec_host_c_files := $(CFILES)
override CC=cc
override AR=ar
override GENERAL_OPTIONS :=
flags = -lclang_rt.builtins-$(ARCH) -DSECUREC_MEMSET_INDIRECT_USE=0 -fstack-protector-all
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DKIRIN
flags += -DHAVE_AUTOCONF -include$(PREBUILD_DIR)/headers/autoconf.h
flags += -nodefaultlibs -fno-omit-frame-pointer
RUNTIME_LIB_FLAG = -lclang_rt.builtins-$(ARCH)

include $(BUILD_OPERATION)/common.mk
