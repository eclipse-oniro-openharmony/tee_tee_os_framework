# drv_shared compile rule
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

SONAME := libdrv_shared$(TARG).so

libdrv_shared_c_files :=

libdrv_shared_c_files += src/io_operations.c
libdrv_shared_c_files += src/drv_share.c
libdrv_shared_c_files += $(TOPDIR)/sys_libs/libdrv_frame/src/drv_thread.c
libdrv_shared_c_files += $(TOPDIR)/sys_libs/libdrv_frame/src/drv_param_ops.c

ifneq ($(CONFIG_TEE_DRV_SERVER_64BIT), )
libdrv_shared_c_files += src/tee_drv_entry.c
libdrv_shared_c_files += src/drv_dispatch.c
libdrv_shared_c_files += src/drv_pm.c
libdrv_shared_c_files += src/drv_operations.c
libdrv_shared_c_files += $(TOPDIR)/drivers/common/drv_pm_check.c

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
flags += -DCRYPTO_MGR_SERVER_ENABLE
libdrv_shared_c_files += src/drv_random.c
endif

ifeq ($(WITH_ENG_VERSION), true)
flags += -DTEE_SUPPORT_CMD_DUMP
flags += -DTEE_SUPPORT_DRV_FD_DUMP
endif
endif

include $(TOPDIR)/mk/lib-common.mk
inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_shared/include

ifneq ($(CONFIG_TEE_DRV_SERVER_64BIT), )
inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/drivers/common/
endif

include $(TOPDIR)/mk/feature-macro.mk

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(INSTALL_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "libdrv_shared [ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

$(BUILD_DIR)/extern.txt: extern.txt $(BUILD_DIR)/export.txt
	@echo "libdrv_shared preprocess ${BUILD_DIR}/extern.txt"
	@mkdir -p $(@D)
	@echo "libdrv_shared extern ${flags}"
	@${CC} ${flags} -P -E -o $@ -x c $<
$(BUILD_DIR)/export.txt: export.txt
	@echo "libdrv_shared preprocess ${BUILD_DIR}/export.txt"
	@mkdir -p $(@D)
	@echo "libdrv_shared export ${flags}"
	@${CC} ${flags} -P -E -o $@ -x c $<

ld-flags :=
ld-flags += -lhwi$(TARG) -lc_shared$(TARG) -lteemem$(TARG) -lteeconfig$(TARG) -lio$(TARG)

ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	ld-flags += --execute-only
endif
endif

ifneq ($(LLVM_TOOLCHAIN_BASEVER), 8.0.1)
ld-flags += -z separate-loadable-segments
endif

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
	ld-flags += -T$(XOM_LIB_LDS)
endif
endif

ifeq ($(xom32_enable), y)
$(MODULE_FILE): $(BUILD_DIR)/extern.txt $(libdrv_shared_objs)
	@echo "libdrv_shared xom32_enable ld-flags is $(ld-flags) [ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): $(BUILD_DIR)/extern.txt $(libdrv_shared_objs)
	@echo "libdrv_shared xom32_disable ld-flags is $(ld-flags) [ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096
	$(VER)$(OBJCOPY) $@
endif


#clean:
#	@echo "clean init"
#	rm -rf $(BUILD_DIR)
