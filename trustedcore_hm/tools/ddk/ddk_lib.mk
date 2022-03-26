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

INCLUDE_PATH += $(SYS_INCLUDE_PATH)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(INNER_SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_INNER_SDK)/teeapi/tui \
                $(PREBUILD_INNER_SDK)/teeapi \
                $(PREBUILD_SDK)/gpapi \
                $(PREBUILD_SDK)/teeapi

include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/llvm-apps-xom.mk
include $(TOPDIR)/mk/llvm-apps-cfi.mk

inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/hm -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH) -I$(PREBUILD_HEADER)/gen/arch/$(ARCH)
inc-flags += $(INCLUDE_PATH:%=-I%)
inc-flags += -I$(THIRD_PARTY_DIR)/bounds_checking_function/include

# c & cpp flags:
flags += -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong
flags += -nodefaultlibs -nostdinc -DHAVE_AUTOCONF -include$(PREBUILD_DIR)/headers/autoconf.h
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG

cxx-flags += -funwind-tables -fexceptions -std=gnu++11 -frtti -fno-builtin
ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	LIB_VENDOR_FLAGS := -execute-only
else
	LIB_VENDOR_FLAGS :=
endif
endif

ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
endif

ifeq ($(CONFIG_TEE_FS_OPER),y)
flags += -DTEE_FS_OPER
endif

ifeq ($(CONFIG_DRV_SEC_ENABLE), true)
flags += -DDRV_SEC_ENABLE
endif

ifeq ($(CONFIG_ASCEND_SEC_ENABLE), true)
flags += -DASCEND_SEC_ENABLE
endif

ifneq ($(findstring $(CONFIG_EPS_FOR_MSP)$(CONFIG_EPS_FOR_990), true),)
flags += -DEPS_ENABLE
endif

ifeq ($(CONFIG_PERSO_ENABLE),y)
flags += -DPERSO_ENABLE
endif

ifeq ($(CONFIG_SSA_SHRINK_MEMORY),y)
flags += -DSSA_SHRINK_MEMORY
endif

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)

# cpp flags:
cxx-flags += -nostdinc++ -static-libstdc++
cxx-flags += -I$(LLVM_INC)
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
