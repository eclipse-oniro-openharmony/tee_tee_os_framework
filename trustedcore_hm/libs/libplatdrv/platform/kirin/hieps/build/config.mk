#########################################################
# Environment initialize
#########################################################
export GCC_COLORS = 'error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'
MAKE_DEBUG ?= 0
NOECHO ?= @

#########################################################
# Options configure
#########################################################
# base parameters
SEC_BUILD_ID := hieps
SEC_OS_TYPE ?= no_os
SEC_TARGET ?= libhieps
SEC_PROJECT := hieps
SEC_SELF_MAKE ?= false
SEC_DFT_ENABLE ?= false
SEC_PRODUCT ?= kirin990
PROJECT_ROOT_DIR ?= $(call abs-dir, $(SEC_ROOT_DIR)/../../..)
ANDROID_TOP_ABS_DIR ?= $(call abs-dir, $(PROJECT_ROOT_DIR)/../../../../../../..)
HIEPS_ROOT_DIR ?= $(ANDROID_TOP_ABS_DIR)/vendor/hisi/confidential/hieps
export SEC_CHIP_TYPE ?= $(if $(chip_type),$(chip_type),cs)
SEC_CHIP_DIR ?= $(SEC_PRODUCT)_$(SEC_CHIP_TYPE)
SEC_OUT_DIR ?= $(SEC_ROOT_DIR)/out/$(SEC_PRODUCT)/$(shell echo $(SEC_TARGET) | tr a-z A-Z)_OBJS
SEC_OUT_LIB = $(SEC_OUT_DIR)/$(SEC_TARGET).a
$(info SEC_SELF_MAKE = $(SEC_SELF_MAKE), MAKECMDGOALS = $(MAKECMDGOALS), SEC_CHIP_DIR = $(SEC_CHIP_DIR))

# initialize
SEC_GLOBAL_CFLAGS :=
SEC_GLOBAL_SFLAGS :=
SEC_GLOBAL_ARFLAGS :=
SEC_CFLAGS :=
SEC_SFLAGS :=

SEC_INCLUDES := \
	-I$(SEC_ROOT_DIR)/include \
	-I$(SEC_ROOT_DIR)/host/include/pal \
	-I$(SEC_ROOT_DIR)/host/include/adapter \
	-I$(SEC_ROOT_DIR)/libseceng/include/cdrmr \
	-I$(SEC_ROOT_DIR)/driver/agent/include \
	-I$(SEC_ROOT_DIR)/libseceng/include/api \
	-I$(SEC_ROOT_DIR)/libseceng/include/hal/$(SEC_PROJECT) \
	-I$(SEC_ROOT_DIR)/libseceng/include/hal \
	-I$(SEC_ROOT_DIR)/libseceng/include/common/$(SEC_PROJECT) \
	-I$(SEC_ROOT_DIR)/libseceng/include/common \
	-I$(SEC_ROOT_DIR)/libseceng/include \
	-I$(SEC_ROOT_DIR)/autotest/framework \
	-I$(call get-chip-dir, $(ANDROID_TOP_ABS_DIR)/vendor/hisi/ap/platform)

# dft configure
ifeq ($(SEC_DFT_ENABLE),true)
SEC_CFLAGS += -DFEATURE_DFT_ENABLE -DFEATURE_AUTOTEST
endif

ifeq ($(strip $(SEC_PRODUCT)),)
$(error not set SEC_PRODUCT)
endif

ifeq ($(strip $(SEC_CHIP_DIR)),)
$(error not set SEC_CHIP_DIR)
endif

SEC_GLOBAL_CFLAGS := $(SEC_INTERNAL_INCLUDE) $(call options-format, $(SEC_GLOBAL_CFLAGS)) $(SEC_INCLUDES)
SEC_GLOBAL_SFLAGS := $(SEC_INTERNAL_INCLUDE) $(call options-format, $(SEC_GLOBAL_SFLAGS)) $(SEC_INCLUDES)
