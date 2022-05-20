DRIVER := hmsysmgr
ifeq ($(CONFIG_ARCH_AARCH32),y)
USE_GNU_CXX := y
endif

# used by common/var.mk
MODULE_FOLDER := $(shell basename $(CURDIR))
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/rule.mk

# default compile target
default: all

PREBUILD_ARCHIVE = hmsysmgr.bin.a

ifeq ($(CONFIG_ARCH_AARCH32),y)
PREBUILD_ARCH_PLAT_LIBS := $(PREBUILD_LIBS)/arm
BUILD_DIR := $(TOPDIR)/output/arm/obj/arm/hmsysmgr
endif

INSTALL_FILE = $(DRV_DIR)/$(DRIVER)
TARGET_FILE  := $(BUILD_DIR)/$(DRIVER)
AR_FILE = $(PREBUILD_ARCH_PLAT_LIBS)/$(PREBUILD_ARCHIVE)
$(eval $(call eval_extracted_objs,$(MODULE_FOLDER),$(AR_FILE),$(BUILD_DIR)))
$(eval $(call eval_extract_ar,$(BUILD_DIR),$(TARGET_FILE),$(AR_FILE)))

ifeq ($(CONFIG_ARCH_AARCH64),y)
LIBS := debug syscalls syscalls_sysmgr cs_sysmgr c_sysmgr fileio mmgr_sysmgr pathmgr security \
	vfs_sysmgr ac hmlog ac_policy asan_sysmgr

ifeq ($(CONFIG_SRAM_PROTECTION),y)
LIBS += openssl
endif

else
LIBS := debug_a32 syscalls_a32 syscalls_sysmgr_a32 cs_sysmgr_a32 c_sysmgr_a32 fileio_a32 mmgr_sysmgr_a32 pathmgr_a32 security_a32\
	vfs_sysmgr_a32 ac_a32 hmlog_a32 ac_policy_a32 asan_sysmgr_a32

ifeq ($(CONFIG_SRAM_PROTECTION),y)
LIBS += openssl_a32
endif

endif


ifeq ($(findstring true, $(CONFIG_REMOTE_ATTESTATION_32BIT) $(CONFIG_REMOTE_ATTESTATION_64BIT)), true)
LIBS += mem_measure${TARG} openssl${TARG}
endif

include $(TOPDIR)/mk/asan.mk

ifeq ($(CONFIG_ARCH_AARCH32),y)
LIB_DIR_A32 := $(OUTPUTDIR)/arm/libs
LINK_LIBS=$(LIBS:%=-l%)
$(eval $(call eval_dep_libs,$(MODULE_FOLDER),$(LIB_DIR_A32),$(LIBS:%=lib%.a)))
LINK_LIBS += -lhwsecurec_a32
else
LINK_LIBS=$(LIBS:%=-l%)
$(eval $(call eval_dep_libs,$(MODULE_FOLDER),$(LIB_DIR),$(LIBS:%=lib%.a)))
LINK_LIBS += -lhwsecurec
endif

hmsysmgr_c-flags += -fPIC
ifeq ($(CONFIG_USER_DEBUG_BUILD), y)
hmsysmgr_c-flags += -g
endif


ifeq ($(CONFIG_ARCH_AARCH64),y)
ifeq (${CONFIG_ENABLE_XOM},y)
hmsysmgr_LDFLAGS += --execute-only
hmsysmgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-$(TEE_ARCH).lds
else
hmsysmgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-unxom-$(TEE_ARCH).lds
endif
else
hmsysmgr_LDFLAGS += -u __vsyscall_ptr  -T $(PREBUILD_TOOLS)/common/boot-app-$(TEE_ARCH).lds
endif

ifeq ($(CONFIG_ARCH_AARCH64),y)
hmsysmgr_LDFLAGS += -L$(LIB_DIR)
hmsysmgr_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/$(PLAT)/libhwsecurec/
else
hmsysmgr_LDFLAGS += -L$(LIB_DIR_A32)
hmsysmgr_LDFLAGS += -L$(TOPDIR)/../../tee_os_kernel/build/arm/$(PLAT)/libhwsecurec_a32/
endif

hmsysmgr_LDFLAGS += --gc-sections -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LINK_LIBS) $(LIBCOMPILER_RT_BUILTINS) $(EH_FILE) --end-group
hmsysmgr_LDFLAGS += -u _hm_start -e _hm_start -z max-page-size=0x1000 -nostdlib --build-id=none -z noexecstack -z now -z relro
ifeq ($(filter y, $(CONFIG_USER_DEBUG_BUILD)), )
hmsysmgr_LDFLAGS += -s
endif
ifeq ($(CONFIG_GCOV),y)
hmsysmgr_LDFLAGS += -lllvm_gcov${TARG}
endif

ifeq ($(CONFIG_SYSSERV_ASLR), y)
	hmsysmgr_LDFLAGS += -pie
endif

$(TARGET_FILE): $(AR_FILE) $(hmsysmgr_dep_libs)
	@echo "[ LD ] $@"
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(VER) $(LD) $(hmsysmgr_extracted_objs) $(hmsysmgr_LDFLAGS) -o $@
	$(VER) $(OBJCOPY) $@
	if [ "$(CONFIG_USER_DEBUG_BUILD)" != "y" ]; then $(STRIP) --strip-debug $@; fi

$(INSTALL_FILE): $(TARGET_FILE)
	@echo "[ INSTALL DRIVER ] $@"
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@cp -rf $< $@

all: $(INSTALL_FILE)
