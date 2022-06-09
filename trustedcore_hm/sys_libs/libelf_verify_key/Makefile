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
flags += -DDYN_TA_SUPPORT_V1
flags += -DDYN_TA_SUPPORT_V2
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V2
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

ifeq ($(ENABLE_TA_LOAD_WHITE_BOX_KEY),true)
flags += -DCONFIG_WHITE_BOX_KEY
endif

libelf_verify_key_c_files := $(wildcard src/*.c)
libelf_verify_key_c_files += $(wildcard src/common/*.c)
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/
inc-flags += -I$(TOPDIR)/drivers/base_mgr/tee_misc_driver/src/
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config

ifeq ($(CONFIG_GENERIC_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/higeneric/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/higeneric/

ifneq ($(ENABLE_TA_LOAD_WHITE_BOX_KEY),true)
ifneq ($(CONFIG_DYN_TA_FORMAT),1)
FILTEROUT_CFILES = src/common/higeneric/wb_tool_128_root_key.c
endif
FILTEROUT_CFILES += src/wb_tool_256_root_key.c
endif
endif
ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_sharemem_key_c_files := $(wildcard src/*.c)
libelf_sharemem_key_c_files += $(wildcard src/sharemem/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/
endif

ifeq ($(CONFIG_KUNPENG_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/kunpeng/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/kunpeng/
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/kunpeng/ecies_keys
endif

ifeq ($(CONFIG_ASCEND_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/ascend/*.c)
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/ascend/
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/ascend/ecies_keys/
ifeq ($(product_name), mdc)
$(info product type is mdc)
flags += -DCONFIG_TA_DECRYPT_ECIES_MDC
else ifeq ($(product_name), mini)
$(info product type is mini)
flags += -DCONFIG_TA_DECRYPT_ECIES_MINI
endif
endif

ifeq ($(CONFIG_HUANGLONG_LOAD_KEY_3072),y)
inc-flags += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/common/huanglong/ecies_keys
endif

ifeq ($(CONFIG_OH_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/openharmony/*.c)
endif

ifeq ($(product_type), cdc)
$(info product type is cdc)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_type), cdc_ace)
$(info product type is cdc_ace)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_name), mdc)
$(info product type is mdc)
flags += -DCONFIG_TA_SIGN_MDC
else ifeq ($(product_name), mini)
$(info product type is mini)
flags += -DCONFIG_TA_SIGN_MINI
else ifeq ($(CONFIG_TA_SIGN_KEY_CBG),true)
flags += -DCONFIG_TA_SIGN_CBG
else ifeq ($(CONFIG_HUANGLONG_LOAD_KEY_3072),y)
flags += -DCONFIG_TA_SIGN_HUANGLONG
endif

ifeq ($(CONFIG_PLAT_HUANGLONG),y)
libelf_verify_key_c_files += ../../platform/huanglong/ta_load/tee_ta_load.c
endif
ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_sharemem_key_c_files))
else
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_verify_key_c_files))
endif

include $(TOPDIR)/mk/lib-common.mk
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
