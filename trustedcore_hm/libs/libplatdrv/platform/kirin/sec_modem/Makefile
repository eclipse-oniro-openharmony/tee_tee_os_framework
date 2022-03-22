SONAME := sec_modem.so
include $(CURDIR)/sec_modem.mk

sec_modem_c_files := $(CFILES)
include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk

DEP_LIB_DIR := $(CURDIR)/output/lib
MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(DEP_LIB_DIR)/$(SONAME)

inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include
inc-flags += -I$(TOPDIR)/sys_libs/libhmdrv_stub/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/inc

ifeq ($(xom32_enable), y)
ld-flags += -T $(XOM_LIB_LDS)
endif

ld-flags += -s

INPUT_PATH := $(abspath $(CURDIR)/output/input)
OUTPUT_PATH :=  $(abspath $(CURDIR)/output/output)
SIGNTOOLS_PATH := $(abspath $(CURDIR)/../../../../../../../itrustee_sdk/build/signtools)
ITrustee_CODE_ROOT_PATH := $(abspath $(CURDIR)/../../../../../../../../../../)

ifeq ($(RELEASE_SIGN), true)
INI_FILE_PATH := $(SIGNTOOLS_PATH)/config_cbg_release.ini
else
INI_FILE_PATH := $(SIGNTOOLS_PATH)/config_cbg_debug_only_sign.ini
endif

target:
ifneq ($(filter $(TARGET_BOARD_PLATFORM), laguna), )
# when platdrv is 32bit
ifneq ($(TARG), )
target: $(INSTALL_FILE)
endif
else
# when platdrv is 64bit
ifeq ($(TARG), )
target: $(INSTALL_FILE)
endif
endif

$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(DEP_LIB_DIR) || mkdir -p $(DEP_LIB_DIR)
	@test -d $(INPUT_PATH) || mkdir -p $(INPUT_PATH)
	@test -d $(OUTPUT_PATH) || mkdir -p $(OUTPUT_PATH)
	@echo "[ INI_FILE_PATH ] $(INI_FILE_PATH)"
	$(VER)cp -rafp $(MODULE_FILE) $(INPUT_PATH)/libcombine.so
	$(VER)cp -rafp $(CURDIR)/manifest.txt $(INPUT_PATH)
	$(info $(shell export NATIVE_CA_SIGN_JAR_PATH=$(ITrustee_CODE_ROOT_PATH)/tools/signcenter/NativeCASign.jar))
	$(CURDIR)/sign_sec_modem.sh $(INPUT_PATH) $(OUTPUT_PATH) $(INI_FILE_PATH)
	$(VER)cp $(CURDIR)/output/output/*.so.sec $(PRODUCT_OUT)/platdrv_libsec_modem.so.sec
	$(VER)rm -rf $(CURDIR)/output

ifeq ($(xom32_enable), y)
$(MODULE_FILE): $(sec_modem_objs)
	@echo "[ LD ] $@"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections -o $@ \
		$^ -L$(PREBUILD_LIBS)/$(ARCH)-$(HM_PLATFORM) --start-group $(ld-flags) $(LIBGCC_FILE) --end-group -nostdlib
	$(VER)$(CURDIR)/output/xom $@
	$(VER)$(OBJCOPY) $@ --remove-section ".xomloc"
else
$(MODULE_FILE): $(sec_modem_objs)
	@echo "[ LD ] $@"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections -o $@ \
		$^ -L$(PREBUILD_LIBS)/$(ARCH)-$(HM_PLATFORM) --start-group $(ld-flags) $(LIBGCC_FILE) --end-group -nostdlib
endif
