# Use gnueabi toolchain to support relro

SONAME := libgm_shared${TARG}.so

flags += -DSM_SUPPORT -DOPENSSL_NO_STDIO
flags += -I$(PREBUILD_HEADER)/gmssl
flags += -I$(PREBUILD_HEADER)/gmssl/openssl
flags += -I$(PREBUILD_HEADER)/gmssl/crypto/ec
flags += -I$(PREBUILD_HEADER)/gmssl/crypto/sm2
flags += -I$(PREBUILD_HEADER)/gmssl/crypto/bn
flags += -I$(PREBUILD_HEADER)/gmssl/crypto/include
flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
libgm_shared_c_files := $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk
MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	LIBGM_SHARED_DFLAGS := -execute-only
else
	LIBGM_SHARED_DFLAGS :=
endif
endif

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
	LIBGM_SHARED_DFLAGS := -T$(XOM_LIB_LDS)
endif
endif

target: $(MODULE_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ifeq ($(xom32_enable), y)
$(MODULE_FILE): extern.txt $(libgm_shared_objs)
	@echo " GMSSL[ LD ] $@"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack -z max-page-size=4096 --gc-sections --version-script=export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group -lgmssl${TARG} $(LIBCOMPILER_RT_BUILTINS) --end-group \
		-nostdlib $(LIBGM_SHARED_DFLAGS)
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): extern.txt $(libgm_shared_objs)
	@echo " GMSSL[ LD ] $@"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack -z max-page-size=4096 --gc-sections --version-script=export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group -lgmssl${TARG} $(LIBCOMPILER_RT_BUILTINS) --end-group \
		-nostdlib $(LIBGM_SHARED_DFLAGS)
endif
