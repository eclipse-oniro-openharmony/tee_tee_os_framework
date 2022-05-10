# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.

DRIVER := crypto_mgr.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

crypto_mgr_c_files += $(wildcard src/*.c) \
                      $(wildcard src/crypto_ioctl/*.c)

ifeq ($(CONFIG_DATA_FALLTHROUGH),y)
flags += -DDATA_FALLTHROUGH
endif

inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/drivers/tee_drv_server/src
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/drivers/common
inc-flags += -I$(TOPDIR)/drivers/platdrv/src
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_shared/src
inc-flags += -I$(TOPDIR)/drivers/base_mgr/crypto_mgr/src/crypto_ioctl/

# Libraries

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk
