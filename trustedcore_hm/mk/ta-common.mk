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
TA_LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack --strip-debug -T$(TOPDIR)/mk/ta_link_64.ld
else
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(xom32_enable),y)
TA_LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_new.xom.ld
flags += -fvisibility=hidden
else
TA_LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_new.ld
flags += -fvisibility=hidden
endif
else
TA_LDFLAGS += -r -d -T$(TOPDIR)/mk/ta_link.ld
endif
endif

LINK_LIBS=$(LIBS:%=-l%)
TA_LDFLAGS += -L$(LIB_DIR)
TA_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk

### HM_NOTE: where added this flags  while compiling hm-teeos
### 	     do it later.
TA_LDFLAGS:=$(filter-out -pie,$(TA_LDFLAGS))
TA_LDFLAGS:=$(filter-out --gc-sections,$(TA_LDFLAGS))
