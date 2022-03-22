TARGET := kms.elf
kms_c_files :=  $(wildcard ./src/*.c)

inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(PREBUILD_DIR)/headers/openssl

flags += -DAPI_LEVEL=3
include $(TOPDIR)/mk/ta-common.mk

target: $(SCRAMBLED_SYMS)

$(SCRAMBLED_SYMS): $(BUILD_DIR)/$(TARGET)
	rm -f $(SCRAMBLED_SYMS)
	$(SCRAMB_SYMS) $(BUILD_DIR)/$(TARGET) $(SCRAMBLED_SYMS) "hikey_970"
	touch $(SCRAMBLED_SYMS)
