# tee_misc_driver compile rule
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

DRIVER := tee_misc_driver.elf

include $(TOPDIR)/mk/feature-macro.mk
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk
-include $(PREBUILD_HM_INC)/.config

tee_misc_driver_c_files := $(wildcard src/*.c)

c-flags += -Wno-implicit-fallthrough
c-flags += -DTA_LOG_LEVEL=2
inc-flags += -I$(PREBUILD_DIR)/headers/ddk
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/sys/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/legacy
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(FRAMEWORK_PATH)/drvmgr/src
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(TOPDIR)/sys_libs/libdynconfmgr/include/
inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TOPDIR)/drivers/common
c-flags += -DCONFIG_MISC_DRIVER
flags += $(TRUSTEDCORE_LOCAL_CFLAGS)

ifeq (${TARG},_a32)
ifeq ($(xom32_enable),y)
	tee_misc_driver_LDFLAGS += -T$(XOM_LDS)
endif
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk

install:
	@echo "tee_misc_driver strip begin"
	@$(READELF) -W -s $(INSTALL_FILE) | grep ' FUNC ' | \
		awk -v path=$(INSTALL_FILE) '{printf " -K "$$8} END {printf(" %s", path)}' | \
		xargs -L 1 -s 262144 $(STRIP)
	@echo "tee_misc_driver strip end"

