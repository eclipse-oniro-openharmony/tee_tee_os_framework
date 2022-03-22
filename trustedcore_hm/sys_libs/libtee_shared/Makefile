
SONAME := libtee_shared$(TARG).so

libtee_shared_c_files := $(wildcard src/*.c)
ifeq ($(CONFIG_GCOV), n)
libtee_shared_c_files := $(addprefix $(TOPDIR)/sys_libs/libtee_shared/,$(libtee_shared_c_files))
endif

inc-flags += -I$(TOPDIR)/drivers/platdrv/include # dynion.h
inc-flags += -I$(TOPDIR)/sys_libs/libtee_shared/include
inc-flags += -I$(TOPDIR)/platform/common/tee_config

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(INSTALL_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ifeq ($(findstring true, $(CONFIG_GATEKEEPER_32BIT) $(CONFIG_GATEKEEPER_64BIT)), true)
flags += -DSUPPORT_GATEKEEPER_TA
inc-flags += -I$(TOPDIR)/sys_apps/gatekeeper/src/task_gatekeeper
endif

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
flags += -DDEF_BUILDUSERMODE
endif

ifeq ($(CONFIG_EXPORT_OPENSSL_SYMBOL), true)
flags += -DSUPPORT_EXPORT_OPENSSL_SYMBOL
endif

ifeq ($(CONFIG_LIBTEE_SHARED_LITE), y)
EXTERN_FILE := lite_extern.txt
EXPORT_FILE := lite_export.txt
ALIAS_FILE  := lite_alias.txt
else ifeq ($(CONFIG_OH_SHARED_LIB), y)
EXTERN_FILE := oh_extern.txt
EXPORT_FILE := oh_export.txt
ALIAS_FILE  := oh_alias.txt
else
EXTERN_FILE := extern.txt
EXPORT_FILE := export.txt
ALIAS_FILE  := alias.txt
endif

${BUILD_DIR}/$(EXTERN_FILE): $(EXTERN_FILE) ${BUILD_DIR}/$(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXTERN_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
${BUILD_DIR}/$(EXPORT_FILE): $(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXPORT_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
ld-flags := -lccmgr$(TARG) -lcrypto_hal$(TARG) -ltimer$(TARG) -lagent$(TARG) -lagent_base$(TARG) -lhwi$(TARG) -lhmdrv$(TARG) \
    -lteeos$(TARG) -lswcrypto_engine$(TARG) -ltaentry$(TARG) -lteeagentcommon_client$(TARG) -lcrypto$(TARG) \
    -lteeconfig$(TARG) -lteemem$(TARG) -lac$(TARG) -lac_policy$(TARG) -ldecouple$(TARG) -lssa$(TARG) -lhuk${TARG} -lteedynsrv$(TARG)

ifeq ($(CONFIG_GCOV),y)
ld-flags += -lllvm_gcov$(TARG)
endif

ifdef CONFIG_RPMB_64BIT
ld-flags += -lrpmb$(TARG)
endif
ld-flags += -lsec_fs_msg$(TARG)

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
ld-flags += -lmbedtls${TARG}
else ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),boringssl)
ld-flags += -lboringssl${TARG}
else
ld-flags += -lopenssl${TARG}
endif

ifneq ($(findstring true, $(CONFIG_TUI_64BIT)$(CONFIG_TUI_32BIT)),)
ld-flags += -ltui$(TARG)
endif

ifeq ($(CONFIG_OTRP_SUPPORT),y)
ld-flags += -lotrp${TARG}
endif

ifeq ($(findstring true, $(CONFIG_SEM) $(CONFIG_SE_SERVICE_32BIT) $(CONFIG_SE_SERVICE_64BIT)), true)
ld-flags += -lse$(TARG)
endif

ALIAS_SYM := $(shell cat $(ALIAS_FILE) | awk '{print "--defsym="$$1}' | tr "\n" " ")

ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	ld-flags += -execute-only
endif
endif

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
	ld-flags += -T$(XOM_LIB_LDS)
endif
endif
ifeq ($(xom32_enable), y)
$(MODULE_FILE): $(BUILD_DIR)/$(EXTERN_FILE) $(libtee_shared_objs)
	@echo "LibTEE [LD] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/$(EXPORT_FILE) -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096 $(ALIAS_SYM)
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): $(BUILD_DIR)/$(EXTERN_FILE) $(libtee_shared_objs)
	@echo "LibTEE [LD] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/$(EXPORT_FILE) -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096 $(ALIAS_SYM)
endif
