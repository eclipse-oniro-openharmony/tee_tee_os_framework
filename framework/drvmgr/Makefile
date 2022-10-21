# drvmgr compile rule
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

DRIVER := drvmgr.elf

override SOURCE_DIR:=$(FRAMEWORK_PATH)/drvmgr

include $(BUILD_CONFIG)/feature-macro.mk
include $(BUILD_CONFIG)/var.mk
include $(TOPDIR)/trustedcore_hm/mk/plat.mk
-include $(PREBUILD_HM_INC)/.config

# it depends on compile order
NO_OBJFILE_SORT = y

# Source files required to build the target
drvmgr_c_files := src/main.c \
		src/drv_dispatch.c \
		src/drv_fd_ops.c \
		src/drv_process_mgr.c \
		src/drv_index_mgr.c \
		src/drv_ipc_mgr.c \
		src/drv_auth.c \
		src/drv_dyn_conf_mgr.c \
		src/drvcall_dyn_conf_mgr.c \
		src/drv_dyn_policy_mgr.c \
		src/base_drv_node.c \
		src/task_mgr.c

ifeq ($(WITH_ENG_VERSION), true)
flags += -DTEE_SUPPORT_DRV_FD_DUMP
endif

ifeq ($(CONFIG_DYN_CONF_DEBUG), true)
flags += -DTEE_SUPPORT_DYN_CONF_DEBUG
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), false)
flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
flags += -DCRYPTO_MGR_SERVER_ENABLE
endif
LIBS :=

c-flags += -Wno-implicit-fallthrough
c-flags += -DTA_LOG_LEVEL=2
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/sys/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/legacy
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(FRAMEWORK_PATH)/drvmgr/src
inc-flags += -I$(DRVLIB)/common/libdrv_frame/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(SYSLIB)/libdynconfmgr/include/
inc-flags += -I$(SYSLIB)/libspawn_common/include/
inc-flags += -I$(TEELIB)/libhmdrv/include/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(SYSLIB)/libelf_verify/include

LIBS += c_shared${TARG}
LIBS += timer${TARG} ac${TARG}
LIBS += teemem${TARG} teeos${TARG} spawn_common${TARG}

ENTRY_POINT := main
LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so
LIBS += drv_frame${TARG}
LIBS += ac_policy${TARG}
LIBS += drv_shared${TARG}

include $(BUILD_DRIVER)/drv-common.mk

flags += $(TRUSTEDCORE_LOCAL_CFLAGS)

LIBS += hmdrv${TARG}
drvmgr_LDFLAGS += --whole-archive -lteeconfig${TARG} --no-whole-archive

install:
	@echo "drvmgr strip begin"
	@$(READELF) -W -s $(INSTALL_FILE) | grep ' FUNC ' | \
		awk -v path=$(INSTALL_FILE) '{printf " -K "$$8} END {printf(" %s", path)}' | \
		xargs -L 1 -s 262144 $(STRIP)
	@echo "drvmgr strip end"

