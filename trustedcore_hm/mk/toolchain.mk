#
#toolchain.mk
#
export GCC_TOOLCHAIN_BASEVER=7.5.0
export GCC_TOOLCHAIN_FULLVER=7.5.0-2019.12
export LLVM_TOOLCHAIN_BASEVER=8.0.1

export TOOLCHAIN_ROOT=$(TOPDIR)/prebuild/toolchains
export GCC_LD_A32 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-arm-linux-gnueabi/bin/arm-linux-gnueabi-ld
export GCC_LD_A64 := $(TOPDIR)/prebuild/toolchains/gcc-linaro-aarch64-linux-gnu/bin/aarch64-linux-gnu-ld

export CLANG_TOOLCHAIN   := $(TOOLCHAIN_ROOT)/clang+llvm/bin
export GCC_TOOLCHAIN_A32 := $(TOOLCHAIN_ROOT)/gcc-linaro-arm-eabi
export GCC_TOOLCHAIN_A64 := $(TOOLCHAIN_ROOT)/gcc-linaro-aarch64-linux-gnu
export GCC_TOOLCHAIN_GNUA32 := $(TOOLCHAIN_ROOT)/gcc-linaro-arm-linux-gnueabi
export PATH := $(CLANG_TOOLCHAIN):$(GCC_TOOLCHAIN_A32)/bin:$(GCC_TOOLCHAIN_A64)/bin:$(GCC_TOOLCHAIN_GNUA32)/bin:$(PATH)
CROSS_COMPILE := $(CLANG_TOOLCHAIN)

CC      := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang
CXX     := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang++
AS      := $(CROSS_COMPILE)/llvm-as
LD      := $(CROSS_COMPILE)/ld.lld
CPP     := $(CROSS_COMPILE)/clang-cpp
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
	GCC_TOOLCHAIN := $(GCC_TOOLCHAIN_GNUA32)
ifeq ("$(compiler-rt)", "exist")
	LIBCOMPILER_RT_BUILTINS := $(TOPDIR)/../../tee_os_kernel/libs/teelib/libcompiler-rt/arm-build/lib/linux/libclang_rt.builtins-arm.a
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
	GCC_TOOLCHAIN := $(GCC_TOOLCHAIN_A64)
ifeq ("$(compiler-rt)", "exist")
	LIBCOMPILER_RT_BUILTINS := $(TOPDIR)/../../tee_os_kernel/libs/teelib/libcompiler-rt/aarch64-build/lib/linux/libclang_rt.builtins-aarch64.a
else
	LIBCOMPILER_RT_BUILTINS := $(PREBUILD_DIR)/libs/aarch64/libclang_rt.builtins-aarch64.a
endif
    flags += -march=armv8-a
endif

SYSROOT := $(GCC_TOOLCHAIN)/$(TARGET_ARCH)/libc
ISYSTEM := $(GCC_TOOLCHAIN)/$(TARGET_ARCH)/libc/usr/include

flags     += --gcc-toolchain=$(GCC_TOOLCHAIN) --sysroot=$(SYSROOT) --target=$(TARGET_ARCH)
cxx-flags += --gcc-toolchain=$(GCC_TOOLCHAIN) --sysroot=$(SYSROOT) --target=$(TARGET_ARCH)
asflags   += --gcc-toolchain=$(GCC_TOOLCHAIN) --sysroot=$(SYSROOT) --target=$(TARGET_ARCH)
ldflags   += --sysroot=$(SYSROOT)

EH_FILE     := $(shell $(CC) $(flags) -print-file-name=libgcc_eh.a)
ATOMIC_LIB  := $(shell $(CXX) $(flags) -print-file-name=libatomic.a)
