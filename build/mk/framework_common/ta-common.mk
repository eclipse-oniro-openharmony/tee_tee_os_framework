TARGET_IS_TA := y
# setup toolchain
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

# for ld flags
ifeq ($(ARCH),aarch64)
LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack --strip-debug
flags += -fvisibility=hidden
else
LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack
flags += -fvisibility=hidden
endif

LINK_LIBS=$(LIBS:%=-l%)
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk

### HM_NOTE: where added this flags  while compiling tee kernel
### 	     do it later.
LDFLAGS:=$(filter-out -pie,$(LDFLAGS))
LDFLAGS:=$(filter-out --gc-sections,$(LDFLAGS))
