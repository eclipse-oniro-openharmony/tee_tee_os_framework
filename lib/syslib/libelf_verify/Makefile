# libelf_verify compile rule, modified by yuanhao34@huawei.com
# Copyright Huawei Technologies Co., Ltd. 2010-2021. All rights reserved.

# Targets
MODULE := libelf_verify${TARG}.a

SOURCE_DIR := $(SYSLIB)/libelf_verify

# Source files required to build the target
CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_load_ext_mf.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_load_key_ops.c))

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), mbedtls)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify_mbedtls.c))
else
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify_openssl.c))
endif

ifneq ($(findstring y, $(CONFIG_APP_TEE_PERM) $(CONFIG_APP_TEE_PERM_A32)),)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_perm_img.c))
else
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_perm_img_stub.c))
endif

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_comm_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_comm_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
endif

LDFLAGS += -z noexecstack

CPPFLAGS += -I$(SYSLIB)/libelf_verify/include
CPPFLAGS += -I$(K_SYSLIB)/libc/include/hm
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(K_THIRDPARTY)/huawei/libwhitebox/
CPPFLAGS += -I$(K_SYSLIB)/libelf/include
CPPFLAGS += -I$(K_SYSLIB)/libirqmgr/include
CPPFLAGS += -I$(TEELIB)/libpermission_service/src
CPPFLAGS += -I$(SERVICES_PATH)/permission_service/src
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee # ta_framework.h
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(K_FRAMEWORK)/teesmcmgr/src
CPPFLAGS += -I$(TOPDIR)/sys_libs/libbase_shared/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libac_policy/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libelf_verify_key/include/
CPPFLAGS += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(K_SYSLIB)/libipc/include # msg_ops.h
CPPFLAGS += -I$(TOPDIR)/sys_libs/libdynconfmgr/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libdynconfbuilder/include
CPPFLAGS += -I$(FRAMEWORK_PATH)/drvmgr/src
CPPFLAGS += -I$(DRIVERS_PATH)/include
CPPFLAGS += -I$(TEELIB)/libtimer/include/
CPPFLAGS += -I$(TOPDIR)/sys_libs/libspawn_common/include/
CPPFLAGS += -I$(K_SYSLIB)/libsyscalls/include # usrsyscall.h
CPPFLAGS += -I$(K_SYSLIB)/libac/include
CPPFLAGS += -I$(K_SYSLIB)/libccmgr_hm/include
CPPFLAGS += -I$(K_SYSLIB)/libfileio/include
CPPFLAGS += -I$(TEELIB)/libhmdrv/include
CPPFLAGS += -I$(K_SYSLIB)/libhmlog/include
CPPFLAGS += -I$(K_SYSLIB)/libhongmeng/include
CPPFLAGS += -I$(K_SYSLIB)/libutils/include # dlist.h
CPPFLAGS += -I$(K_SYSLIB)/libmmgr/include # mmgrapi_common.h

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), mbedtls)
CPPFLAGS += -I$(K_TEELIB)/libmbedtls/mbedtls/include
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
CPPFLAGS += -I$(K_TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(K_TEELIB)/libopenssl/openssl/crypto
endif

# Source files required to build the target
CPPFLAGS += -I$(SOURCE_DIR)/include/
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TOPDIR)/sys_libs/libelf_verify_key/src/

CFLAGS += -DOPENSSL_ENABLE

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
CFLAGS += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
CFLAGS += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
CFLAGS += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
