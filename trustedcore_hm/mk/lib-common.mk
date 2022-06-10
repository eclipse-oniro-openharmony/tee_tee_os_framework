# llvm c++ libs and headers
PREBUILD_TOOLCHAIN := $(TOPDIR)/prebuild/toolchains/llvm_sysroot
LLVM_INC := $(PREBUILD_TOOLCHAIN)/$(ARCH)/include
LLVM_LIB := $(PREBUILD_TOOLCHAIN)/$(ARCH)/lib
# setup toolchain
TARGET_IS_SYS := y
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk
include $(TOPDIR)/mk/common.mk

# use musl lib c headers.
inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/hm -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_HEADER)/gen/arch/$(ARCH)
inc-flags += $(INCLUDE_PATH:%=-I%)
inc-flags += -I$(TEE_SECUREC_DIR)/include

# c & cpp flags:
flags += -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong
flags += -nodefaultlibs -nostdinc
flags += -DARM_PAE=1 -DHAVE_AUTOCONF -include$(PREBUILD_DIR)/headers/autoconf.h
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG

ifeq (${TARG},)
	LIB_VENDOR_FLAGS :=
endif

LIB_VENDOR_FLAGS += -z separate-loadable-segments

ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
endif

ifneq ($(findstring $(CONFIG_EPS_FOR_MSP)$(CONFIG_EPS_FOR_990), true),)
flags += -DEPS_ENABLE
endif

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)

# cpp flags:
cxx-flags += -nostdinc++ -static-libstdc++
cxx-flags += -I$(LLVM_INC)
flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk
