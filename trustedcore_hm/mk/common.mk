MODULE_FOLDER := $(shell basename $(CURDIR))

ifeq ($(ARCH),)
$(error ARCH must be set, now we support both arm and aarch64)
endif

# default target
default: all

include $(TOPDIR)/mk/asan.mk

inc-flags += -I$(TEE_SECUREC_DIR)/include
INCLUDE_PATH += $(PREBUILD_DIR)/headers/
INCLUDE_PATH += $(TOPDIR)/tools/

# all target flags for both c & c++ compiler
ifneq ($(TARGET_IS_HOST),y)
flags += -Oz
else
#gcc optimization flags
flags += -Os
endif

ifeq ($(TARGET_IS_HOST),)
ifeq ($(CONFIG_LLVM_LTO),y)
ifeq ($(CONFIG_GCOV),)
flags += -flto -fsplit-lto-unit
endif
endif
endif

flags += -Wall -Wextra
# other options
flags += -fno-omit-frame-pointer -fno-short-enums
flags += -DHAVE_AUTOCONF
flags += -DVFMW_EXTRA_TYPE_DEFINE -DENV_SOS_KERNEL
ifeq ($(CONFIG_UBSAN),y)
flags += -fsanitize=bounds-strict -fsanitize-address-use-after-scope -fsanitize-undefined-trap-on-error
endif

## argument pointer will be aligned with 1 Byte
ifneq ($(TARGET_IS_HOST),y)
ifeq ($(ARCH),arm)
ifeq (${CONFIG_UNALIGNED_ACCESS},y)
flags += -munaligned-access -fmax-type-align=1
endif
endif
endif
flags += -fno-builtin

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
flags += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

# all target for c++ compiler
cxx-flags += -funwind-tables -fexceptions -std=gnu++11 -frtti -fno-builtin

#include the sub makefile as needed
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/rule.mk
#shoule keep the same value with hm-apps/trustedcore_hm/config.mk

include $(TOPDIR)/mk/plat.mk
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
CFLAGS   += ${TRUSTEDCORE_PLATFORM_FLAGS}
CPPFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
CXXFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
ASFLAGS  += ${TRUSTEDCORE_PLATFORM_FLAGS}
# always generate compiling object file rule
$(eval $(call eval_objs,$(MODULE_FOLDER)))

# compile libs
ifneq ($(MODULE),)
INSTALL_FILE := $(LIB_DIR)/$(MODULE)
MODULE_FILE  := $(BUILD_DIR)/$(MODULE)
target: $(MODULE_FILE)
$(eval $(call eval_libs,$(MODULE_FOLDER),$(MODULE_FILE)))
## install libs
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL MODULE ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(INSTALL_FILE)
	touch $(INSTALL_FILE)
endif

# compile apps
ifneq ($(TARGET),)
INSTALL_FILE := $(APP_DIR)/$(TARGET)
TARGET_FILE  := $(BUILD_DIR)/$(TARGET)
target: $(TARGET_FILE)
ifneq ($(PREBUILD_ARCHIVE),)
AR_FILE = $(PREBUILD_ARCH_PLAT_LIBS)/$(PREBUILD_ARCHIVE)
$(warning MODULE ${MODULE_FOLDER} lib_dir=${LIB_DIR})
$(eval $(call eval_extracted_objs,$(MODULE_FOLDER),$(AR_FILE),$(BUILD_DIR)))
$(eval $(call eval_extract_ar,$(BUILD_DIR),$(TARGET_FILE),$(AR_FILE)))
endif
$(eval $(call eval_dep_libs,$(MODULE_FOLDER),$(LIB_DIR),$(LIBS:%=lib%.a)))
$(eval $(call eval_apps,$(MODULE_FOLDER),$(TARGET_FILE)))
$(INSTALL_FILE): $(TARGET_FILE)
	@test -d $(APP_DIR) || mkdir -p $(APP_DIR)
	@echo "[ INSTALL APP ] $(TARGET_FILE)"
	$(VER)cp -rafp $(TARGET_FILE) $(INSTALL_FILE)
	touch $(INSTALL_FILE)
endif

# compile drivers
ifneq ($(DRIVER),)
INSTALL_FILE := $(DRV_DIR)/$(DRIVER)
TARGET_FILE  := $(BUILD_DIR)/$(DRIVER)
target: $(TARGET_FILE)
ifneq ($(PREBUILD_ARCHIVE),)
AR_FILE = $(PREBUILD_ARCH_PLAT_LIBS)/$(PREBUILD_ARCHIVE)
$(eval $(call eval_extracted_objs,$(MODULE_FOLDER),$(AR_FILE),$(BUILD_DIR)))
$(eval $(call eval_extract_ar,$(BUILD_DIR),$(TARGET_FILE),$(AR_FILE)))
endif
$(eval $(call eval_dep_libs,$(MODULE_FOLDER),$(LIB_DIR),$(LIBS:%=lib%.a)))
$(eval $(call eval_drivers,$(MODULE_FOLDER),$(TARGET_FILE)))
$(INSTALL_FILE): $(TARGET_FILE)
	@test -d $(DRV_DIR) || mkdir -p $(DRV_DIR)
	@echo "[ INSTALL DRIVER ] $(TARGET_FILE)"
	$(VER)cp -rafp $(TARGET_FILE) $(INSTALL_FILE)
	touch $(INSTALL_FILE)
endif

ifeq ($(SCRAMBLE_ME), y)
TARGET_NAME    := $(basename $(notdir $(INSTALL_FILE)))
SCRAMBLED_SYMS := $(BUILD_DIR)/scrambled_$(TARGET_NAME)_syms.txt
$(SCRAMBLED_SYMS): $(INSTALL_FILE) $(SCRAMB_SYMS)
	rm -f $(SCRAMBLED_SYMS)
	$(VER)$(SCRAMB_SYMS) $(INSTALL_FILE) $(SCRAMBLED_SYMS) "hikey_970"
	touch $(SCRAMBLED_SYMS)
else
SCRAMBLED_SYMS :=
endif

scramble: $(SCRAMBLED_SYMS)

# all the target
all: target install scramble

## this is ugly..
ifneq ($(EXPORT_HDRS),)
install_headers:
	@echo "cp export_hdrs=${EXPORT_HDRS} installdir=${HDR_INSTALL_DIR}"
	@ cp -raf $(EXPORT_HDRS) $(HDR_INSTALL_DIR)/
else
install_headers:

endif
install: $(INSTALL_FILE)
