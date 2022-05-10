#
# @TAG(HUAWEI)
#

# Targets
TARGET := hmfilemgr

# used by common/var.mk
MODULE_FOLDER := $(shell basename $(CURDIR))
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/toolchain.mk

BOOTIMG := $(STAGE_DIR)/bootfs.img
PREBUILD_FILEMGR_OBJ := $(PREBUILD_APPS)/$(TARGET)/src

hm_filemgr_objects := $(BUILD_DIR)/src/get_ramfs_data.o

INSTALL_FILE := $(APP_DIR)/$(TARGET)
# default compile target
ifeq ($(CONFIG_SCRAMBLE_SYMS), y)
hmfilemgr_c-flags += -fvisibility=hidden
TARGET_NAME = $(basename $(notdir $(TARGET)))
SCRAMBLED_SYMS := $(BUILD_DIR)/scrambled_$(TARGET_NAME)_syms.txt
$(SCRAMBLED_SYMS): $(INSTALL_FILE)
	rm -f $(SCRAMBLED_SYMS)
	$(SCRAMB_SYMS) $(INSTALL_FILE) $(SCRAMBLED_SYMS) "hikey_970"
	touch $(SCRAMBLED_SYMS)
else
SCRAMBLED_SYMS :=
endif
default: $(INSTALL_FILE) $(SCRAMBLED_SYMS)

# build hmfilemgr
$(INSTALL_FILE): $(BUILD_DIR)/$(TARGET)
	@echo "[ INSTALL APP ] $@"
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@cp -rf $< $@
ifeq ($(CONFIG_ARCH_AARCH64),y)
LIBS := hongmeng ramfs debug syscalls pathmgr \
	ac security hmlog ac_policy ipc
ifeq ($(CONFIG_FILEMGR_EMBEDDED), y)
LIBS += c_sysmgr vfs_sysmgr mmgr_sysmgr mmgr fileio syscalls_sysmgr
else
LIBS += c vfs mmgr
endif
TARGET_ARCH := $(TARGET_ARCH_64)
GCC_TOOLCHAIN := $(GCC_TOOLCHAIN_A64)
else
LIBS := hongmeng_a32 ramfs_a32 debug_a32 syscalls_a32 pathmgr_a32 \
	ac_a32 security_a32 hmlog_a32 ac_policy_a32 ipc_a32
ifeq ($(CONFIG_FILEMGR_EMBEDDED), y)
LIBS += c_sysmgr_a32 vfs_sysmgr_a32 mmgr_sysmgr_a32 mmgr_a32 fileio_a32 syscalls_sysmgr_a32
else
LIBS += c_a32 vfs_a32 mmgr_a32
endif
TARGET_ARCH := $(TARGET_ARCH_32)
GCC_TOOLCHAIN := $(GCC_TOOLCHAIN_A32)
endif
# the main part of hmfilemgr
LIBS += hmfilemgr

ifdef CONFIG_KASAN
LIBS += asan
endif
ENTRY_POINT=_hm_start
LINK_LIBS=$(LIBS:%=-l%)
ifeq ($(CONFIG_ARCH_AARCH64),y)
LINK_LIBS += -lhwsecurec
else
LINK_LIBS += -lhwsecurec_a32
endif
hmfilemgr_dep_libs = $(addprefix $(LIB_DIR)/,$(LLIBS:%=lib%.a))

ifeq ($(CONFIG_FILEMGR_EMBEDDED), y)
hmsysmgr_lib := $(PREBUILD_LIBS)/$(TEE_ARCH)/hmsysmgr.bin.a
else
hmsysmgr_lib :=
endif

hmfilemgr_c-flags  += --gcc-toolchain=$(GCC_TOOLCHAIN) --sysroot=$(SYSROOT) --target=$(TARGET_ARCH)
hmfilemgr_c-flags  += -Wall -Wextra -std=gnu11 -Oz -fno-builtin -fPIC -Wformat=2
hmfilemgr_c-flags  += -Wdate-time -Werror -Wfloat-equal -Wshadow -fno-common -fno-strict-aliasing -pipe
hmfilemgr_c-flags  += -fstack-protector-strong -mtune=cortex-a53 -march=armv8-a -ffunction-sections -fdata-sections -fno-omit-frame-pointer
hmfilemgr_c-flags  += -include$(PREBUILD_HEADER)/autoconf.h
hmfilemgr_c-flags  += $(gcc-plugin-c-flags)

ifeq ($(CONFIG_ARCH_AARCH64),y)
ifeq (${CONFIG_ENABLE_XOM},y)
filemgr_LDFLAGS += --execute-only
filemgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-$(TEE_ARCH).lds
else
filemgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-unxom-$(TEE_ARCH).lds
endif
else
filemgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-$(TEE_ARCH).lds
endif

filemgr_LDFLAGS += -L$(LIB_DIR)
ifeq ($(CONFIG_ARCH_AARCH64),y)
filemgr_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/$(PLAT)/libhwsecurec/
else
filemgr_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/$(PLAT)/libhwsecurec_a32/
endif
filemgr_LDFLAGS += --gc-sections -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LINK_LIBS) $(LIBCOMPILER_RT_BUILTINS) --end-group
filemgr_LDFLAGS += -u _hm_start -e _hm_start -z max-page-size=0x1000 -nostdlib --build-id=none -z noexecstack -z relro -z now
ifeq ($(CONFIG_GCOV),y)
filemgr_LDFLAGS += -lllvm_gcov${TARG}
endif

ifeq ($(filter y, $(CONFIG_SCRAMBLE_SYMS) $(CONFIG_USER_DEBUG_BUILD)), )
filemgr_LDFLAGS += -s
endif
ifeq ($(CONFIG_SYSSERV_ASLR), y)
	filemgr_LDFLAGS += -pie
endif

$(BUILD_DIR)/$(TARGET): $(hm_filemgr_objects) $(hmfilemgr_dep_libs)
	@echo "[ LD ] $@"
	$(VER) $(LD) $(hm_filemgr_objects) $(hmsysmgr_lib) $(filemgr_LDFLAGS) -o $@
	$(VER) $(OBJCOPY) $@
	if [ "$(CONFIG_USER_DEBUG_BUILD)" != "y" ]; then $(STRIP) --strip-debug $@; fi

$(BUILD_DIR)/src/get_ramfs_data.o: $(CURDIR)/src/get_ramfs_data.c $(BOOTIMG)
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(VER)$(CC) $(hmfilemgr_c-flags) -DBOOTFS_IMG="$(filter %.img, $^)" \
		-c -o $@ $(filter %.c,$^)
