# platdrv compile rule
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

DRIVER := platdrv.elf

override SOURCE_DIR:=$(TOPDIR)/drivers/platdrv

include $(TOPDIR)/mk/feature-macro.mk
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk
-include $(PREBUILD_HM_INC)/.config

# platdrv don't support sort objdect file
# it depends on compile order
NO_OBJFILE_SORT = y

ifeq ($(CONFIG_SRE_AUDIT),y)
flags += -DSRE_AUDIT
endif

ifneq ($(findstring $(CONFIG_EPS_FOR_MSP)$(CONFIG_EPS_FOR_990), true),)
flags += -DEPS_ENABLE
endif

ifeq ($(CONFIG_EPS_FOR_990), true)
flags += -DEPS_FOR_990
endif

ifeq ($(CONFIG_DATA_FALLTHROUGH),y)
flags += -DDATA_FALLTHROUGH
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

# Source files required to build the target
platdrv_c_files := src/main.c           \
		src/tc_drv.c            \
		src/stub.c              \
		src/drv_pal.c           \
		src/sre_dev_relcb.c     \
		src/sre_hwi_ipc.c       \
		src/platdrv.c           \
		src/param_check.c       \
		src/sys_modem.c         \
		src/sre_hwi.c       \
		src/drv_cache_flush.c   \
		src/platdrv_hash.c      \
		src/rand_update.c       \
		$(TOPDIR)/drivers/common/drv_call_check.c \
		$(TOPDIR)/drivers/common/drv_pm_check.c \
		$(TOPDIR)/sys_libs/libdrv_shared/src/io_operations.c

ifeq ($(CONFIG_DRIVER_DYN_MOD), true)
platdrv_c_files += src/drv_mod.c
endif

platdrv_c_files += platform/common/crypto/crypto_syscall.c \
		platform/common/crypto/crypto_syscall_ae.c \
		platform/common/crypto/crypto_syscall_cipher.c \
		platform/common/crypto/crypto_syscall_common.c \
		platform/common/crypto/crypto_syscall_dh.c \
		platform/common/crypto/crypto_syscall_ecc.c \
		platform/common/crypto/crypto_syscall_ecdh.c \
		platform/common/crypto/crypto_syscall_hash.c \
		platform/common/crypto/crypto_syscall_hmac.c \
		platform/common/crypto/crypto_syscall_pbkdf2.c \
		platform/common/crypto/crypto_syscall_derive_key.c \
		platform/common/crypto/crypto_syscall_rsa.c

platdrv_c_files += src/boot_sharedmem.c
platdrv_c_files += $(TOPDIR)/drivers/base_mgr/tee_misc_driver/src/drv_sharedmem.c

ifeq ($(CONFIG_M_DRIVER), true)
platdrv_c_files += src/vendor_syscall.c
endif

platdrv_c_files += $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/platdrv/drv_hash_init.c

LIBS :=
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/modules/platdrv_common.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platdrv/mk/platdrv_config.mk
platdrv_c_files += $(CFILES)

c-flags += -Wno-implicit-fallthrough
ifeq ($(CONFIG_PLATDRV_64BIT), true)
flags += -DPLATDRV_64
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/include
endif
inc-flags += -I$(PREBUILD_DIR)/headers/ddk
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/hmapi
inc-flags += -I$(PREBUILD_DIR)/headers/ddk/legacy
inc-flags += -I$(PREBUILD_HEADER)/sys/stackprotect
c-flags += -I$(SOURCE_DIR)/include
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/platform/common/tee_config
inc-flags += -I$(TOPDIR)/drivers/common
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/drivers/platdrv/src
inc-flags += -I$(TOPDIR)/drivers/base_mgr/tee_misc_driver/src
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_frame/include/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel # sre_rwroot.h
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platdrv/include
inc-flags += -I$(TOPDIR)/vendor/$(PLATFORM_NAME)/libvendor_shared/include
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_shared/include/

inc-flags += -I$(TOPDIR)../../tee_os_kernel/libs/syslib/libsyscalls/include

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

LIBS += agent${TARG} hwi${TARG} c_shared${TARG} agent_base${TARG} crypto${TARG}
LIBS += timer${TARG} ac${TARG} hongmeng${TARG} ipc${TARG} io${TARG}
LIBS += teemem${TARG} teeconfig${TARG} teeos${TARG} crypto_hal${TARG}
ifeq ($(CONFIG_DX_ENABLE), true)
LIBS += dx_cc7${TARG}
endif

ifeq ($(CONFIG_LIB_TIMEMGR), y)
LIBS += timemgr${TARG}
endif
ENTRY_POINT := main
DRV_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so
LIBS += hmdrv_stub${TARG}
LIBS += drv_frame${TARG}
LIBS += ac_policy${TARG}
LIBS += fileio${TARG}

# sanitity will disable gc-section, need to add all dependence libs
ifeq ($(CONFIG_KASAN),y)
LIBS += ccmgr${TARG} hmdrv${TARG}
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
LIBS += openssl${TARG}
endif
endif

include $(TOPDIR)/mk/drv-common.mk

ALIAS_FILE  := alias.txt
ALIAS_SYM := $(shell cat $(ALIAS_FILE) | awk '{print "-D"$$1}' | tr "\n" " ")
# k->u function rename
flags += $(ALIAS_SYM)

flags += $(TRUSTEDCORE_LOCAL_CFLAGS)

ifeq ($(CONFIG_GCOV),y)
$(BUILD_DIR)/src/%.o: c-flags += -g --coverage
endif

platdrv_LDFLAGS += -z separate-loadable-segments

# for DECLARE_TC_DRV, prevent ".tc_drv_descs" section from being merged
ifeq (${TARG},)
platdrv_LDFLAGS += -T$(SOURCE_DIR)/linker64.ld
endif

ifeq (${TARG},)
ifeq (${CONFIG_ENABLE_XOM},y)
	platdrv_LDFLAGS += --execute-only
endif
endif

ifeq (${TARG},_a32)
ifeq ($(CONFIG_ENABLE_XOM32),y)
ifeq ($(xom32_enable),y)
platdrv_LDFLAGS += -T$(SOURCE_DIR)/linker.xom.ld
else
platdrv_LDFLAGS += -T$(SOURCE_DIR)/linker.ld
endif
else
platdrv_LDFLAGS += -T$(SOURCE_DIR)/linker.ld
endif
endif

ifeq ($(CONFIG_DRIVER_DYN_MOD), true)
	platdrv_LDFLAGS += --dynamic-list=export.txt
endif

#ifeq ($(CONFIG_PLATDRV_64BIT), false)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/platdrv/mk/platdrv_binary.mk
#endif

# should set after include platdrv_binary.mk since LIBS_THIRD_VENDOR defined in platdrv_binary.mk
platdrv_LDFLAGS += --whole-archive $(LIBS_THIRD_VENDOR) -no-whole-archive

# use -L 1 -s 262144 to make sure that xargs will not wrap the arguments

install:
	@echo "platdrv strip begin"
	@$(READELF) -W -s $(INSTALL_FILE) | grep ' FUNC ' | \
		awk -v path=$(INSTALL_FILE) '{printf " -K "$$8} END {printf(" %s", path)}' | \
		xargs -L 1 -s 262144 $(STRIP)
	@echo "platdrv strip end"

