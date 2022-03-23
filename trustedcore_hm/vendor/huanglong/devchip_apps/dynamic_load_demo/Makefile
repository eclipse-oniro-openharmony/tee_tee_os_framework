BINARY = 39258f09-2701-443e-96f1-d51730d197f8
TA_NAME = task_hisi_dynamic_demo

# Secure os type is TRUSTEDCORE
TA_COMPILE_TOOL=gcc-linaro-7.4.1-2019.02-x86_64_arm-eabi
SDK_TOOLCHAINS_DIR := $(CURDIR)/../../../../tools/linux/toolchains
TEE_TOOLCHAINS_DIR := $(CURDIR)/../../secureos/itrustee/hm_os/prebuild/toolchains

TA_SDK_CROSS_COMPILE := $(shell if [ -d "$(SDK_TOOLCHAINS_DIR)/$(TA_COMPILE_TOOL)" ]; then echo "y"; fi;)

ifeq ($(strip $(TA_SDK_CROSS_COMPILE)), y)
CROSS_COMPILE ?= $(SDK_TOOLCHAINS_DIR)/$(TA_COMPILE_TOOL)/bin/arm-eabi-
else
CROSS_COMPILE ?= $(TEE_TOOLCHAINS_DIR)/$(TA_COMPILE_TOOL)/bin/arm-eabi-
endif
TA_DEV_KIT_DIR ?= $(CURDIR)/../../secureos/itrustee/ta_dev_dir

O ?= $(CURDIR)/out

include $(TA_DEV_KIT_DIR)/mk/ta_common.mk
