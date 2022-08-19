# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_SYS := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk

inc-flags += $(INCLUDE_PATH:%=-I%)
# use musl lib c headers.

# c & cpp flags:
flags += -fdata-sections -ffunction-sections
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(SVC_PARTITIAL_LINK), y)
ifeq ($(ARCH),aarch64)
DRV_LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -z max-page-size=4096 -T$(TOPDIR)/mk/ta_link_64.ld
flags += -fvisibility=hidden
else
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(xom32_enable),y)
DRV_LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_new.xom.ld
flags += -fvisibility=hidden
else
DRV_LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_new.ld
flags += -fvisibility=hidden
endif
else
DRV_LDFLAGS += -r -d -T$(TOPDIR)/mk/ta_link.ld
endif #CONFIG_DYNLINK
endif #ARCH

LINK_LIBS=$(LIBS:%=-l%)
DRV_LDFLAGS += -L$(LIB_DIR)
DRV_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)
else
DRV_LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
DRV_LDFLAGS += -L$(LIB_DIR)
DRV_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
DRV_LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=4096
endif #SVC_PARTITIAL_LINK

flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk
