# LLVM c++ libs and headers
PREBUILD_TOOLCHAIN := $(TOPDIR)/prebuild/toolchains/llvm_sysroot
LLVM_LIB := $(PREBUILD_TOOLCHAIN)/$(ARCH)/lib

# cpp flags:
cxx-flags += -nostdinc++
cxx-flags += -I$(LLVM_INC)

# load cpp library dynamically or statically
ifeq ($(ENABLE_CPP), true)
ifeq ($(ENABLE_CPP_STATIC), false)
CPP_LIB :=
ifeq ($(ARCH),arm)
CPP_LIB += -lc++_shared_a32
CPP_LIB += $(ATOMIC_LIB)
else
CPP_LIB += -lc++_shared
endif
DRV_LDFLAGS += $(CPP_LIB) --eh-frame-hdr --gc-sections  -L$(LLVM_LIB) --allow-shlib-undefined
else
CPP_LIB :=
ifeq ($(ARCH),arm)
CPP_LIB += $(ATOMIC_LIB)
DRV_LDFLAGS += -L$(OUTPUTDIR)/arm/libs
CPP_LIB += -lc++_static -lc++abi -lunwind
else
CPP_LIB += -lc++_static -lc++abi
DRV_LDFLAGS += -L$(OUTPUTDIR)/aarch64/libs
endif
DRV_LDFLAGS += $(CPP_LIB) --eh-frame-hdr --gc-sections  -L$(LLVM_LIB)  --allow-shlib-undefined
endif
endif
