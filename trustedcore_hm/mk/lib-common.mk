# llvm c++ libs and headers
PREBUILD_TOOLCHAIN := $(TOPDIR)/prebuild/toolchains/llvm_sysroot
LLVM_INC := $(PREBUILD_TOOLCHAIN)/$(ARCH)/include
# setup toolchain
TARGET_IS_SYS := y
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

flags += -fdata-sections -ffunction-sections

ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

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

include $(TOPDIR)/mk/llvm-apps-cfi.mk
