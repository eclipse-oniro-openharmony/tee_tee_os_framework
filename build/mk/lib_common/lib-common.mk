# llvm c++ libs and headers
PREBUILD_TOOLCHAIN := $(TOPDIR)/prebuild/toolchains/llvm_sysroot
LLVM_INC := $(PREBUILD_TOOLCHAIN)/$(ARCH)/include
# setup toolchain
TARGET_IS_SYS := y
include $(BUILD_CONFIG)/var.mk
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

flags += -fdata-sections -ffunction-sections

ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
endif

ifneq ($(findstring $(CONFIG_EPS_FOR_MSP)$(CONFIG_EPS_FOR_990), true),)
flags += -DEPS_ENABLE
endif

# cpp flags:
cxx-flags += -nostdinc++ -static-libstdc++
cxx-flags += -I$(LLVM_INC)
flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk
