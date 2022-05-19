
SONAME := libbase_shared$(TARG).so

libbase_shared_c_files := $(wildcard src/*.c)
ifeq ($(CONFIG_GCOV), n)
libbase_shared_c_files := $(addprefix $(TOPDIR)/sys_libs/libbase_shared/,$(libbase_shared_c_files))
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(INSTALL_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
flags += -DDEF_BUILDUSERMODE
endif

ifeq ($(CONFIG_EXPORT_OPENSSL_SYMBOL), true)
flags += -DSUPPORT_EXPORT_OPENSSL_SYMBOL
endif

EXTERN_FILE := extern.txt
EXPORT_FILE := export.txt
ALIAS_FILE  := alias.txt

${BUILD_DIR}/$(EXTERN_FILE): $(EXTERN_FILE) ${BUILD_DIR}/$(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXTERN_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
${BUILD_DIR}/$(EXPORT_FILE): $(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXPORT_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<

ld-flags := -lc$(TARG) -lhmlog$(TARG) -ltimer$(TARG)

ifeq ($(CONFIG_GCOV),y)
ld-flags += -lllvm_gcov$(TARG)
endif

ALIAS_SYM := $(shell cat $(ALIAS_FILE) | awk '{print "--defsym="$$1}' | tr "\n" " ")

ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	ld-flags += --execute-only
endif
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
ld-flags += -lmbedtls${TARG}
else
ld-flags += -lopenssl${TARG}
endif

ld-flags += -z separate-loadable-segments

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
	ld-flags += -T$(XOM_LIB_LDS)
endif
endif

ifeq ($(xom32_enable), y)
$(MODULE_FILE): $(BUILD_DIR)/$(EXTERN_FILE) $(libbase_shared_objs)
	@echo "LibBASE [LD] $@ LIB_DIR=$(LIB_DIR) ld-flags is $(ld-flags) libbase_shared_objs is $(libbase_shared_objs)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/$(EXPORT_FILE) -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096 $(ALIAS_SYM)
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): $(BUILD_DIR)/$(EXTERN_FILE) $(libbase_shared_objs)
	@echo "LibBASE [LD] $@ LIB_DIR=$(LIB_DIR) ld-flags is $(ld-flags) libbase_shared_objs is $(libbase_shared_objs)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/$(EXPORT_FILE) -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096 $(ALIAS_SYM)
	$(VER)$(OBJCOPY) $@
endif
