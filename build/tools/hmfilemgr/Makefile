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
default: $(INSTALL_FILE)

# build hmfilemgr
$(INSTALL_FILE): $(BUILD_DIR)/$(TARGET)
	@echo "[ INSTALL APP ] $@"
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@cp -rf $< $@
ifeq ($(CONFIG_ARCH_AARCH64),y)
LIBS := hongmeng ramfs debug syscalls pathmgr \
	ac security hmlog ac_policy ipc

LIBS += c vfs mmgr
TARGET_ARCH := $(TARGET_ARCH_64)
else
LIBS := hongmeng_a32 ramfs_a32 debug_a32 syscalls_a32 pathmgr_a32 \
	ac_a32 security_a32 hmlog_a32 ac_policy_a32 ipc_a32
LIBS += c_a32 vfs_a32 mmgr_a32
TARGET_ARCH := $(TARGET_ARCH_32)
endif
# the main part of hmfilemgr
LIBS += hmfilemgr
ENTRY_POINT=_hm_start
LINK_LIBS=$(LIBS:%=-l%)
ifeq ($(CONFIG_ARCH_AARCH64),y)
LINK_LIBS += -lhwsecurec
else
LINK_LIBS += -lhwsecurec_a32
endif
hmfilemgr_dep_libs = $(addprefix $(LIB_DIR)/,$(LLIBS:%=lib%.a))

hmsysmgr_lib :=

hmfilemgr_c-flags  += --target=$(TARGET_ARCH)
hmfilemgr_c-flags  += -Wall -Wextra -std=gnu11 -Oz -fno-builtin -fPIC -Wformat=2
hmfilemgr_c-flags  += -Wdate-time -Werror -Wfloat-equal -Wshadow -fno-common -fno-strict-aliasing -pipe
hmfilemgr_c-flags  += -fstack-protector-strong -mtune=cortex-a53 -march=armv8-a -ffunction-sections -fdata-sections -fno-omit-frame-pointer
hmfilemgr_c-flags  += -include$(PREBUILD_HEADER)/autoconf.h
hmfilemgr_c-flags  += $(gcc-plugin-c-flags)

ifeq ($(CONFIG_ARCH_AARCH64),y)
filemgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-unxom-$(TEE_ARCH).lds
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

filemgr_LDFLAGS += -s
ifeq ($(CONFIG_SYSSERV_ASLR), y)
	filemgr_LDFLAGS += -pie
endif

$(BUILD_DIR)/$(TARGET): $(hm_filemgr_objects) $(hmfilemgr_dep_libs)
	@echo "[ LD ] $@"
	$(VER) $(LD) $(hm_filemgr_objects) $(hmsysmgr_lib) $(filemgr_LDFLAGS) -o $@
	$(VER) $(OBJCOPY) $@
	$(STRIP) --strip-debug $@

$(BUILD_DIR)/src/get_ramfs_data.o: $(CURDIR)/src/get_ramfs_data.c $(BOOTIMG)
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(VER)$(CC) $(hmfilemgr_c-flags) -DBOOTFS_IMG="$(filter %.img, $^)" \
		-c -o $@ $(filter %.c,$^)
