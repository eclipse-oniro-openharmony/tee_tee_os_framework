TARGET_IS_TA := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

# c & cpp flags:
ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

# for ld flags
ifeq ($(ARCH),aarch64)
LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack --strip-debug -T$(TOPDIR)/mk/ta_link_64.ld
flags += -fvisibility=hidden
else
ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_new.ld
flags += -fvisibility=hidden
else
LDFLAGS += -r -d -T$(TOPDIR)/mk/ta_link.ld
endif
endif

LINK_LIBS=$(LIBS:%=-l%)
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk

### HM_NOTE: where added this flags  while compiling hm-teeos
### 	     do it later.
LDFLAGS:=$(filter-out -pie,$(LDFLAGS))
LDFLAGS:=$(filter-out --gc-sections,$(LDFLAGS))
