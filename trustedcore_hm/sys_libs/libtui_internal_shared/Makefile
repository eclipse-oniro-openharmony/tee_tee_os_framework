SONAME := libtui_internal_shared${TARG}.so


libtui_internal_shared${TARG}_c_files := $(wildcard src/*.c)

include $(TOPDIR)/mk/lib-common.mk

ifeq (${CONFIG_ENABLE_XOM},y)
	LIBTUI_INTERNAL_SHARED_DFLAGS := -execute-only
else
	LIBTUI_INTERNAL_SHARED_DFLAGS :=
endif

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
	xom32_ldflags := -T$(XOM_LIB_LDS)
endif
endif

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)
target: $(MODULE_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE) $(LIB_DIR)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

ifeq (${TARG},)
$(MODULE_FILE): extern.txt
	@test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	@echo "[ LD ] $@"
	$(VER)$(LD) --shared -X -EL -z text -z now -m aarch64elf -z relro -z noexecstack -z max-page-size=4096 --gc-sections --version-script=export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) \
		-lpng${TARG} -lzlib${TARG} -lfreetype $(LIBCOMPILER_RT_BUILTINS) -nostdlib $(LIBTUI_INTERNAL_SHARED_DFLAGS)
endif

ifeq (${TARG}, _a32)
ifeq ($(xom32_enable), y)
$(MODULE_FILE): extern.txt
	@test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	echo "[ LD ] $@"
	$(VER)$(LD) $(xom32_ldflags) --shared -X -EL -z text -z now -m armelf_linux_eabi -z relro -z noexecstack --gc-sections --version-script=export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) \
		-lpng${TARG} -lzlib${TARG} -lfreetype${TARG} $(LIBCOMPILER_RT_BUILTINS) -nostdlib
	$(VER)$(XOM) $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): extern.txt
	@test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	echo "[ LD ] $@"
	$(VER)$(LD) $(xom32_ldflags) --shared -X -EL -z text -z now -m armelf_linux_eabi -z relro -z noexecstack --gc-sections --version-script=export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) \
		-lpng${TARG} -lzlib${TARG} -lfreetype${TARG} $(LIBCOMPILER_RT_BUILTINS) -nostdlib
endif
endif
