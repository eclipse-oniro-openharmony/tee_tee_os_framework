SONAME := libvendor_shared$(TARG).so

libvendor_shared_c_files := $(wildcard src/*.c)
libvendor_shared_c_files += $(wildcard $(TOPDIR)/vendor/common/src/*.c)
libvendor_shared_c_files += $(wildcard src/efuse/*.c)
libvendor_shared_c_files += $(wildcard src/hsm_upgrade/*.c)
libvendor_shared_c_files += $(wildcard src/scmi/*.c)
libvendor_shared_c_files += $(wildcard src/sec/*.c)
libvendor_shared_c_files += $(wildcard $(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/src/*.c)
libvendor_shared_c_files += $(wildcard src/hsm_pg_info_get/*.c)
libvendor_shared_c_files += $(wildcard src/sfc/*.c)

inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/efuse
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/sec/include/
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/sfc

# for hsm_client
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/ascend/efuse
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/efuse
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/hsm_upgrade

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
inc-flags += -DDEF_BUILDUSERMODE
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(MODULE_FILE)

$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ifeq (${TARG},)
$(MODULE_FILE): $(libvendor_shared_objs)
	@echo "[ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections  -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group $(LIB_VENDOR_FLAGS) \
		$(LIBCOMPILER_RT_BUILTINS) --end-group -nostdlib -z max-page-size=4096
endif

ifeq (${TARG}, _a32)
$(MODULE_FILE): $(libvendor_shared_objs)
	@echo "[ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections  -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group  \
		$(LIBCOMPILER_RT_BUILTINS) --end-group -nostdlib
endif
