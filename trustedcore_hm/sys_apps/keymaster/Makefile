# TARGET is a TA app
TARGET := keymaster.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)
include $(TOPDIR)/mk/feature-macro.mk

keymaster_c_files += $(wildcard task_keymaster/*.c)
keymaster_c_files += $(wildcard task_keymaster/km_keyblob/*.c)
keymaster_c_files += $(wildcard task_keymaster/whitebox/*.c)
keymaster_c_files += $(wildcard task_keymaster/km_attest/*.c)
keymaster_c_files += $(wildcard task_keymaster/km_crypto/*.c)
keymaster_c_files += $(wildcard task_keymaster/km_sys/*.c)
flags += -I$(TOPDIR)/sys_apps/keymaster/task_keymaster/whitebox
flags += -I$(TOPDIR)/sys_apps/keymaster/task_keymaster/include
flags += -I$(TOPDIR)/sys_apps/keymaster/task_keymaster/
inc-flags += -I$(TOPDIR)/sys_apps/keymaster/task_keymaster/
inc-flags += -I$(TOPDIR)/sys_apps/keymaster/task_keymaster/include/
flags += -DAPI_LEVEL=3

ifeq (${TARG},_a32)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
keymaster_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
keymaster_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif
endif

# Libraries
LIBS :=

flags += -Wall -Wextra -Werror
ifeq (${TARG},)
ifeq ($(CONFIG_MTK_BOOT_INFO), true)
flags += -DMTK_BOOT_INFO
endif
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
endif

flags += -DKEYMASTER_ITRATION_TIMES=$(GATEKEEPER_ITRATION_TIMES)
flags += -DDERIVE_ROOT_INTERNAL_ITRATIONS=$(DERIVE_ROOT_INTERNAL_ITRATIONS)
flags += -DCFG_TEE_KEYMASTER_ENHANCED_KEY
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),boringssl)
flags += -DBORINGSSL_ENABLE
inc-flags += -I$(PREBUILD_HEADER)/boringssl
else
inc-flags += -I$(PREBUILD_HEADER)/openssl
flags += -DOPENSSL_ENABLE
endif
inc-flags += -I$(TOPDIR)/sys_libs/libccmgr/include # ccmgr_ops_ext.h
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config

include $(TOPDIR)/mk/ta-common.mk

keymaster_LDFLAGS  += --start-group $(LIBCOMPILER_RT_BUILTINS) --end-group
