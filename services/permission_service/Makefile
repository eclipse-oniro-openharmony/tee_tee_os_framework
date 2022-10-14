# Copyright Huawei Technologies Co., Ltd. 2010-2022. All rights reserved.

# TARGET is an app
TARGET := permission_service${TARG}.elf

include $(TOPDIR)/mk/var.mk
CFILES := $(wildcard src/*.c)
CFILES += $(wildcard src/auth/tee_auth_sign_rsa.c)

# these libs are for elf verify
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    whitebox${TARG}       \
    dynconfmgr${TARG}     \
    dynconfbuilder${TARG}

inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libpermission_service/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(K_SYSLIB)/libsyscalls/include
inc-flags += -I$(K_SYSLIB)/libutils/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteemem/include # mem_ops_ext.h
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext/
inc-flags += -I$(TEELIB)/libteeconfig/include/kernel/
inc-flags += -I$(TEELIB)/libtimer/include/
inc-flags += -I$(SYSLIB)/libspawn_common/include/
inc-flags += -I$(TEELIB)/libssa/include/
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(K_SYSLIB)/libhongmeng/include
inc-flags += -I$(K_SYSLIB)/libhmlog/include
inc-flags += -I$(K_SYSLIB)/libmmgr_sysmgr/include
inc-flags += -I$(K_SYSLIB)/libmmgr_sysmgr/src
inc-flags += -I$(K_SYSLIB)/libmmgr/include
inc-flags += -I$(K_SYSLIB)/libac/include
inc-flags += -I$(K_SYSLIB)/libipc/include
inc-flags += -I$(SYSLIB)/libelf_verify/include
inc-flags += -I$(TEELIB)/libpermission_service/src
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(SYSLIB)/libdynconfmgr/include/
inc-flags += -I$(SYSLIB)/libdynconfbuilder/include/
inc-flags += -I$(SERVICES_PATH)/permission_service/src
inc-flags += -I$(SERVICES_PATH)/permission_service/src/auth/tee_auth_sign_rsa.h

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(K_TEELIB)/libopenssl/openssl/include
inc-flags += -I$(K_TEELIB)/libopenssl/openssl/crypto
inc-flags += -I$(K_TEELIB)/libopenssl/openssl/crypto/include
endif

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif

ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
CPPFLAGS += -DDYN_IMPORT_CERT=1
CFILES := $(filter-out , $(CFILES))
endif

CFLAGS += -fvisibility=hidden
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl)
CFLAGS += -DOPENSSL_ENABLE
endif

include $(TOPDIR)/mk/ta-common.mk
include $(TOPDIR)/mk/feature-macro.mk
