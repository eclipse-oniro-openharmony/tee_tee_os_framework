# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_SYS := y
# setup toolchain
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk
LLVM_INC := $(PREBUILD_DIR)/headers/libc++

inc-flags += $(INCLUDE_PATH:%=-I%)
# use musl lib c headers.
inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_HEADER)/gen/arch/$(ARCH) -I$(PREBUILD_LIBC_INC)/hm
## for some header file include "alltypes.h" directly.
inc-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits


# c & cpp flags:
flags += -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong
#flags += -Wno-format -nodefaultlibs -nostdinc
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG
flags += -include$(PREBUILD_DIR)/headers/autoconf.h
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)

ifeq ($(CONFIG_TEE_FS_OPER),y)
flags += -DTEE_FS_OPER
endif

ifeq ($(CONFIG_LLVM_LTO),y)
flags += -flto -fsplit-lto-unit
endif

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(ARCH),aarch64)
ifneq ($(EH_FILE),libgcc_eh.a)
RUNTIME_LIB_FLAG += $(EH_FILE)
endif
endif

ifeq (${CONFIG_ENABLE_XOM},y)
ifeq ($(ARCH),aarch64)
	DRV_LDFLAGS += -execute-only
endif
endif

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

ifeq ($(CONFIG_GCOV),y)
ifeq ($(ARCH),aarch64)
DRV_LDFLAGS += -lllvm_gcov
else
DRV_LDFLAGS += -lllvm_gcov_a32
endif
endif

ifeq ($(filter y, $(CONFIG_SCRAMBLE_SYMS) $(CONFIG_USER_DEBUG_BUILD)), )
DRV_LDFLAGS += -s
endif

flags += $(INCLUDES)

include $(TOPDIR)/mk/llvm-apps-cfi.mk
