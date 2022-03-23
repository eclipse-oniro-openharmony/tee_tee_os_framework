SONAME := libvendor_shared$(TARG).so

FILES := $(wildcard src/*.c)
libvendor_shared_c_files := $(filter-out src/se_status.c, $(FILES))
libvendor_shared_c_files += $(wildcard src/driver_api/*.c)
libvendor_shared_c_files += $(wildcard src/driver_api_uni/*.c)
ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT)$(CONFIG_SE_SERVICE_64BIT)),)
libvendor_shared_c_files += src/se_status.c
endif
libvendor_shared_c_files += $(wildcard $(TOPDIR)/vendor/common/src/*.c)

inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/common/include
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/vendor/$(PLATFORM_NAME)/libvendor_shared/include
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
inc-flags += -DDEF_BUILDUSERMODE
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(MODULE_FILE)

ifeq ($(xom32_enable), y)
LIB_VENDOR_FLAGS += -T $(XOM_LIB_LDS)
endif

$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ld-flags := -lsec_flash_client${TARG}

$(BUILD_DIR)/extern.txt: extern.txt $(BUILD_DIR)/export.txt
	@echo "preprocess ${BUILD_DIR}/extern.txt"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
$(BUILD_DIR)/export.txt: export.txt
	@echo "preprocess ${BUILD_DIR}/export.txt"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<

ifeq ($(xom32_enable), y)
$(MODULE_FILE): $(BUILD_DIR)/extern.txt $(libvendor_shared_objs)
	@echo "[ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group  $(ld-flags) $(LIB_VENDOR_FLAGS) \
		$(LIBCOMPILER_RT_BUILTINS) --end-group -nostdlib -z max-page-size=4096
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): $(BUILD_DIR)/extern.txt $(libvendor_shared_objs)
	@echo "[ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group  $(ld-flags) $(LIB_VENDOR_FLAGS) \
		$(LIBCOMPILER_RT_BUILTINS) --end-group -nostdlib -z max-page-size=4096
endif
