# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_DRV := y
# setup toolchain
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

flags += -fdata-sections -ffunction-sections

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=0x1000

flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk
