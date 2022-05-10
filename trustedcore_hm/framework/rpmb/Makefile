# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

# Targets
DRIVER := rpmb${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk
rpmb_c_files += $(wildcard src/*.c)
inc-flags += -I$(TOPDIR)/framework/rpmb/include
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/vendor/ascend/libvendor_shared/src/libhsm_client/include
inc-flags += -I$(TOPDIR)/sys_libs/libcrypto_hal/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/drivers/include

ifeq ($(CFG_TEE_RPMB_SUPPORT), y)
inc-flags += -I$(TOPDIR)/vendor/huanglong/libdevchip_api/include
flags += -DCFG_TEE_RPMB_SUPPORT
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

# Libraries
LIBS := rpmbagent${TARG} \
        zlib${TARG} \
        sec_fs${TARG}

ifeq ($(CONFIG_DYNLINK),y)
DRV_LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk
ifeq ($(CONFIG_ADD_STRIP),y)
DRV_LDFLAGS += -s
endif
DRV_LDFLAGS += $(LIBCOMPILER_RT_BUILTINS)

ifeq ($(CONFIG_HSM), true)
flags += -DTEE_SUPPORT_HSM
endif
