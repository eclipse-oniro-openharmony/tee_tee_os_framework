# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_SYS := y
# setup toolchain
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

# c & cpp flags:
flags += -fdata-sections -ffunction-sections

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(SVC_PARTITIAL_LINK), y)
ifeq ($(ARCH),aarch64)
LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -z max-page-size=4096
flags += -fvisibility=hidden
else
ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack
flags += -fvisibility=hidden
else
LDFLAGS += -r -d
endif #CONFIG_DYNLINK
endif #ARCH

LINK_LIBS=$(LIBS:%=-l%)
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)
else
LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=4096
endif #SVC_PARTITIAL_LINK

flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk
