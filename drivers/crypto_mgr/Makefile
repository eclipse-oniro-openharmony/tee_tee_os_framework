# Copyright Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.

DRIVER := crypto_mgr.elf

include $(TOPDIR)/mk/var.mk

crypto_mgr_c_files += $(wildcard src/*.c) \
                      $(wildcard src/crypto_ioctl/*.c)

inc-flags += -I$(FRAMEWORK_PATH)/drvmgr/src
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRVLIB)/common/libdrv_frame/include
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_shared/src
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl/

# Libraries

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk
