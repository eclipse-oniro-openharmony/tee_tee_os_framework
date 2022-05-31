# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_DRV := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk

inc-flags += $(INCLUDE_PATH:%=-I%)
# use musl lib c headers.
c-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_HEADER)/gen/arch/$(ARCH) -I$(PREBUILD_LIBC_INC)/hm
## for some header file include "alltypes.h" directly.
c-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits


# c & cpp flags:
flags += -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong
flags += -nodefaultlibs
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG
flags += -include$(PREBUILD_DIR)/headers/autoconf.h

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(ARCH),aarch64)
ifneq ($(EH_FILE),libgcc_eh.a)
RUNTIME_LIB_FLAG += $(EH_FILE)
endif
endif

ifeq ($(CONFIG_LLVM_LTO),y)
flags += -flto -fsplit-lto-unit
endif

DRV_LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
DRV_LDFLAGS += -L$(LIB_DIR)
DRV_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
DRV_LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=0x1000
DRV_LDFLAGS += -z separate-loadable-segments

ifeq ($(filter y, $(CONFIG_USER_DEBUG_BUILD)), )
DRV_LDFLAGS += -s
endif

flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk
