arch_list := arm aarch64

## packaging for board platform
export TARGET_BOARD_PLATFORM ?= mt6885

# for bootfs size
HM_BOOTFS_SIZE ?= "8000K"

# hmos release version
export HM_SDK_VER := hm-teeos-release

# export toolchain path
export GCC_TOOLCHAIN_BASEVER=7.5.0
export GCC_TOOLCHAIN_FULLVER=7.5.0-2019.12
export LLVM_TOOLCHAIN_BASEVER=8.0.1

export HM_TOOLCHAIN_A32 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-arm-eabi/bin
export HM_TOOLCHAIN_GNUA32 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-arm-linux-gnueabi/bin
export HM_TOOLCHAIN_A64 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-aarch64-linux-gnu/bin
export PATH := $(HM_TOOLCHAIN_A32):$(HM_TOOLCHAIN_GNUA32):$(HM_TOOLCHAIN_A64):$(PATH)
ifeq ($(TEE_ARCH),aarch64)
export HM_TOOLCHAIN := HM_TOOLCHAIN_A64
else
export HM_TOOLCHAIN := HM_TOOLCHAIN_GNUA32
endif

export TOOLCHAIN_ROOT=$(TOPDIR)/prebuild/toolchains
export GCC_LD_A32 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-arm-linux-gnueabi/bin/arm-linux-gnueabi-ld
export GCC_LD_A64 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-ld

#get var.mk export
include $(TOPDIR)/mk/var.mk
WITH_MTK_PLATFORM := 1
WITH_CHIP_MT6885 := 25 # MTK
ifeq ($(TARGET_BOARD_PLATFORM), mt6885)
TRUSTEDCORE_PLATFORM_CHOOSE := WITH_MTK_PLATFORM
	PLATFORM_NAME := mtk
	CHIP_NAME     := mt6885
	PRODUCT_NAME  := phone
endif
ifeq ($(strip $(PRODUCT_NAME)), )
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(CHIP_NAME)/chip.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/common/chip.mk
else
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/chip.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/chip.mk
endif

TRUSTEDCORE_PLATFORM_FLAGS += \
	-DTRUSTEDCORE_PHY_TEXT_BASE=$(TRUSTEDCORE_PHY_TEXT_BASE) \
	-DTRUSTEDCORE_PHY_IMAGE_LOAD_BASE=$(TRUSTEDCORE_PHY_IMAGE_LOAD_BASE) \
	-DTRUSTEDCORE_CHIP_CHOOSE=$(TRUSTEDCORE_CHIP_CHOOSE)
TRUSTEDCORE_PLATFORM_FLAGS += \
	-DTRUSTEDCORE_PLATFORM_CHOOSE=$(TRUSTEDCORE_PLATFORM_CHOOSE) \
	-DWITH_KIRIN_PLATFORM=$(WITH_KIRIN_PLATFORM) \
	-DWITH_MTK_PLATFORM=$(WITH_MTK_PLATFORM) \
	-DWITH_CHIP_MT6873=$(WITH_CHIP_MT6873) \
	-DWITH_CHIP_MT6853=$(WITH_CHIP_MT6853) \
	-DWITH_CHIP_MT6885=$(WITH_CHIP_MT6885)
