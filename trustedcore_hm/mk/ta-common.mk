TARGET_IS_TA := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk
include $(TOPDIR)/mk/common.mk

# use musl lib c headers.
inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)
inc-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits
inc-flags += $(INCLUDE_PATH:%=-I%)

# c & cpp flags:
flags += -fPIC
flags += -nostdinc -nodefaultlibs -fstack-protector-strong
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG
flags += -include$(PREBUILD_DIR)/headers/autoconf.h
ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

ifeq (${CONFIG_ENABLE_XOM},y)
ifeq ($(ARCH),aarch64)
TA_LDFLAGS += --execute-only
endif
endif

TA_LDFLAGS += -z separate-loadable-segments

# for ld flags
ifeq ($(ARCH),aarch64)
ifeq ($(CONFIG_USER_DEBUG_BUILD),y)
TA_LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack -T$(TOPDIR)/mk/ta_link_64.ld
else
TA_LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack --strip-debug -T$(TOPDIR)/mk/ta_link_64.ld
endif
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

ifeq ($(filter y, $(CONFIG_SCRAMBLE_SYMS) $(CONFIG_USER_DEBUG_BUILD)), )
TA_LDFLAGS += -s
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

# to compile libfuzzer-specific TA
ifeq (${ARCH}, aarch64)
ifeq ($(CONFIG_LIBFUZZER_SERVICE_64BIT), true)
include $(TOPDIR)/mk/libfuzzer_cflags.mk
endif
endif
