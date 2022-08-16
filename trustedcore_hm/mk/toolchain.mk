#
#toolchain.mk
#
export LLVM_TOOLCHAIN_BASEVER=8.0.1

export TOOLCHAIN_ROOT=$(TEE_CLANG_DIR)

export CLANG_TOOLCHAIN   := $(TOOLCHAIN_ROOT)
export PATH := $(CLANG_TOOLCHAIN):$(PATH)
CROSS_COMPILE := $(CLANG_TOOLCHAIN)

CC      := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang
CXX     := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang++
AS      := $(CROSS_COMPILE)/llvm-as
LD      := $(CROSS_COMPILE)/ld.lld
CPP     := $(TOPDIR)/kernel/clang-cpp
# disable ar creating debug
AR      := $(CROSS_COMPILE)/llvm-ar 2>/dev/null
NM      := $(CROSS_COMPILE)/llvm-nm
OBJCOPY := $(CROSS_COMPILE)/llvm-objcopy
READELF := $(CROSS_COMPILE)/llvm-readelf
STRIP   := $(CROSS_COMPILE)/llvm-strip
RANLIB  := $(CROSS_COMPILE)/llvm-ranlib

XOM     := $(TOPDIR)/tools/xom/xom
XOM_TOOLCHAIN   := $(TOOLCHAIN_ROOT)/xom
LLC     := $(XOM_TOOLCHAIN)/bin/llc
CC-XOM  := $(XOM_TOOLCHAIN)/bin/clang-xom
CXX-XOM := $(XOM_TOOLCHAIN)/bin/clang-xom
LD-XOM  := $(XOM_TOOLCHAIN)/bin/ld.lld
XOM_LIB_LDS := $(TOPDIR)/mk/linker.lib.xom.ld
XOM_LDS     := $(TOPDIR)/mk/linker.xom.ld

export LLC CC-XOM CXX-XOM XOM_LIB_LDS XOM_LDS XOM LD-XOM
export CC CXX AS LD CPP AR NM OBJCOPY READELF STRIP


# clang need `--target=$(TARGET_ARCH)` option
export TARGET_ARCH_32 := arm-linux-gnueabi
export TARGET_ARCH_64 := aarch64-linux-gnu

compiler-rt = $(shell if [ -d $(TOPDIR)/../open_source ]; then echo "exist"; else echo "noexist"; fi)
ifeq ($(ARCH), arm)
	TARGET_ARCH := $(TARGET_ARCH_32)
ifeq ("$(compiler-rt)", "exist")
	LIBCOMPILER_RT_BUILTINS := $(TEE_COMPILER_DIR)/lib/arm-linux-ohosmusl/libclang_rt.builtins.a
else
	LIBCOMPILER_RT_BUILTINS := $(PREBUILD_DIR)/libs/arm/libclang_rt.builtins-arm.a
endif
ifeq (${CONFIG_THUMB_SUPPORT},y)
    flags += -mthumb
endif
ifeq ($(CONFIG_ARM_CORTEX_A15),y)
    flags += -march=armv7ve
endif
ifeq ($(CONFIG_ARM_CORTEX_A53),y)
    flags += -march=armv8-a
endif
else
	TARGET_ARCH := $(TARGET_ARCH_64)
ifeq ("$(compiler-rt)", "exist")
	LIBCOMPILER_RT_BUILTINS := $(TEE_COMPILER_DIR)/lib/aarch64-linux-ohosmusl/libclang_rt.builtins.a
else
	LIBCOMPILER_RT_BUILTINS := $(PREBUILD_DIR)/libs/aarch64/libclang_rt.builtins-aarch64.a
endif
    flags += -march=armv8-a
endif

flags     += --target=$(TARGET_ARCH)
cxx-flags += --target=$(TARGET_ARCH)
asflags   += --target=$(TARGET_ARCH)
