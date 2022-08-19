# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_DRV := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

flags += -fdata-sections -ffunction-sections

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

DRV_LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
DRV_LDFLAGS += -L$(LIB_DIR)
DRV_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
DRV_LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=0x1000

flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk
