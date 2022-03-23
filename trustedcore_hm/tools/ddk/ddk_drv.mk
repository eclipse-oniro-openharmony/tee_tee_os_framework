# hm entrypoint
ENTRY_POINT ?= _hm_start

TARGET_IS_DRV := y
################################### give common compilation options #################################

PREBUILD_SDK  := $(PREBUILD_DIR)/headers/sdk
PREBUILD_INNER_SDK  := $(PREBUILD_DIR)/headers/inner_sdk
PREBUILD_DDK  := $(PREBUILD_DIR)/headers/ddk
PREBUILD_SYS  := $(PREBUILD_DIR)/headers/sys
PREBUILD_KERNEL := $(PREBUILD_DIR)/headers/kernel
SDK_INCLUDE_PATH_COMMON += $(PREBUILD_SDK)/teeapi/common \
                           $(PREBUILD_SDK)/gpapi/common
KERNEL_INCLUDE_PATH_COMMON = $(PREBUILD_KERNEL)/ \
                             $(PREBUILD_KERNEL)/uapi \
                             $(PREBUILD_KERNEL)/arch/arm/uapi

INNER_SDK_INCLUDE_PATH_COMMON += $(HDR_L_DIR) \
                                 $(PREBUILD_INNER_SDK)/teeapi/common \
                                 $(PREBUILD_INNER_SDK)/legacy/ \
                                 $(PREBUILD_INNER_SDK)/legacy/uapi \
                                 $(PREBUILD_INNER_SDK)/hmapi

DDK_INCLUDE_PATH_COMMON += $(PREBUILD_DDK)/hmapi/ \
                           $(PREBUILD_DDK)/legacy/uapi \
                           $(PREBUILD_DDK)/legacy/

SYS_INCLUDE_PATH += $(PREBUILD_SYS)/hmapi \
                    $(PREBUILD_SYS)/teeapi \
                    $(PREBUILD_SYS)/legacy \
                    $(PREBUILD_SYS)/legacy/uapi

INCLUDE_PATH += $(SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(INNER_SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_DDK)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_INNER_SDK)/teeapi
INCLUDE_PATH += $(PREBUILD_SDK)/gpapi
INCLUDE_PATH += $(PREBUILD_DIR)/headers/
INCLUDE_PATH += $(TOPDIR)/tools/

include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk

inc-flags += $(INCLUDE_PATH:%=-I%)
inc-flags += -I$(TOPDIR)/thirdparty/huawei/libhwsecurec/include/libhwsecurec/
inc-flags += -I$(TOPDIR)/thirdparty/huawei/libhwsecurec/include/

# use musl lib c headers.
c-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_HEADER)/gen/arch/$(ARCH) -I$(PREBUILD_LIBC_INC)/hm
## for some header file include "alltypes.h" directly.
c-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits


# c & cpp flags:
flags += -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong
flags += -nodefaultlibs
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG
flags += -include$(PREBUILD_DIR)/headers/autoconf.h

cxx-flags += -funwind-tables -fexceptions -std=gnu++11 -frtti -fno-builtin

RUNTIME_LIB_FLAG := $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(ARCH),aarch64)
ifneq ($(EH_FILE),libgcc_eh.a)
RUNTIME_LIB_FLAG += $(EH_FILE)
endif
endif

DRV_LDFLAGS += -u __vsyscall_ptr --gc-sections -pie -z relro -z now
DRV_LDFLAGS += -L$(LIB_DIR)
DRV_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) --start-group $(LIBS:%=-l%) $(RUNTIME_LIB_FLAG) --end-group
DRV_LDFLAGS +=  -nostdlib -u $(ENTRY_POINT) -e $(ENTRY_POINT) -z max-page-size=0x1000
ifeq ($(CONFIG_GCOV),y)
ifeq ($(ARCH),aarch64)
DRV_LDFLAGS += -lllvm_gcov
else
DRV_LDFLAGS += -lllvm_gcov_a32
endif
endif
flags += $(INCLUDES)

################################### compile and ld #################################
MODULE_FOLDER := $(shell basename $(CURDIR))
$(warning "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ $(MODULE_FOLDER) @@@@@@@@@@@@@@@@@ $(CURDIR)")
default: all

include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/rule.mk
export TARGET_BOARD_PLATFORM ?= mt6885

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
CFLAGS   += ${TRUSTEDCORE_PLATFORM_FLAGS}
CPPFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
CXXFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
ASFLAGS  += ${TRUSTEDCORE_PLATFORM_FLAGS}

$(eval $(call eval_objs,$(MODULE_FOLDER)))

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

all: target scramble $(INSTALL_FILE)
