# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

DRIVER := misc_driver.elf
SCRAMBLE_ME :=

include $(BUILD_CONFIG)/feature-macro.mk
include $(BUILD_CONFIG)/var.mk
-include $(PREBUILD_HM_INC)/.config

misc_driver_c_files := $(wildcard src/*.c)

c-flags += -Wno-implicit-fallthrough
c-flags += -DTA_LOG_LEVEL=2
inc-flags += -I$(PREBUILD_DIR)/headers/ddk
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/sys/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/legacy
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRIVERS_PATH)/misc_driver/src
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(FRAMEWORK_PATH)/drvmgr/src
inc-flags += -I$(DRVLIB)/common/libdrv_frame/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(SYSLIB)/libdynconfmgr/include/
inc-flags += -I$(SYSLIB)/libspawn_common/include/
c-flags += -DCONFIG_MISC_DRIVER
flags += $(TRUSTEDCORE_LOCAL_CFLAGS)

SVC_PARTITIAL_LINK = y
include $(BUILD_SERVICE)/svc-common.mk

install: $(SCRAMBLED_SYMS)
	@echo "misc_driver strip begin"
	@$(READELF) -W -s $(INSTALL_FILE) | grep ' FUNC ' | \
		awk -v path=$(INSTALL_FILE) '{printf " -K "$$8} END {printf(" %s", path)}' | \
		xargs -L 1 -s 262144 $(STRIP)
	@echo "misc_driver strip end"

