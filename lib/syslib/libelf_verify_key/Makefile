# libload_key
# Copyright Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

# TARGET is a lib
MODULE := libelf_verify_key${TARG}.a

include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/feature-macro.mk

ifneq ($(chip_type),cs2)
flags += -DWITH_CHIP_CS
else
flags += -DWITH_CHIP_CS2
endif

ifeq ($(CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION),true)
flags += -DSUPPORT_SIGN_KEY_RELEASE_DEBUG_ISOLATION
endif

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

libelf_verify_key_c_files := $(wildcard src/*.c)
libelf_verify_key_c_files += $(wildcard src/common/*.c)
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src/

ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_sharemem_key_c_files := $(wildcard src/*.c)
libelf_sharemem_key_c_files += $(wildcard src/sharemem/*.c)
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
endif

ifeq ($(CONFIG_OH_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/openharmony/*.c)
endif

ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_sharemem_key_c_files))
else
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_verify_key_c_files))
endif

include $(TOPDIR)/mk/lib-common.mk
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
