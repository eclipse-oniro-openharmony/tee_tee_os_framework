# Copyright Huawei Technologies Co., Ltd. 2010-2022. All rights reserved.
DRIVER := ssa${TARG}.elf

CFILES := $(wildcard src/*/*.c)

include $(BUILD_CONFIG)/var.mk

CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext/
CPPFLAGS += -I$(TEELIB)/libteeos/src/TEE/permission_service
CPPFLAGS += -I$(TEELIB)/libteemem/include # mem_ops_ext.h
CPPFLAGS += -I$(K_SYSLIB)/libipc/include # msg_ops.h
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libtee_shared/include
CPPFLAGS += -I$(TEELIB)/libssa/src
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(K_TEELIB)/libse/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libpermission_service/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(K_SYSLIB)/libac/include
CPPFLAGS += -I$(K_SYSLIB)/libhmlog/include
CPPFLAGS += -I$(SERVICES_PATH)/huk_service/src
CPPFLAGS += -I$(SERVICES_PATH)/huk_service/include
CPPFLAGS += -I$(SERVICES_PATH)/ssa/src/secure_storage_agent
CPPFLAGS += -I$(SERVICES_PATH)/ssa/src
CPPFLAGS += -I$(TOPDIR)/libs/libcrypto_common
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
CPPFLAGS += -I$(K_TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(K_TEELIB)/libopenssl/openssl/crypto
endif

CFLAGS += -fvisibility=hidden

LDFLAGS += -z noexecstack

ifeq (${CONFIG_TEE_TEST_UT},y)
    CFLAGS += -DTEE_TEST_UT
endif

ifeq ($(TARGET_IS_ARM32),y)
CFLAGS += -mno-thumb
endif

ifeq ($(CONFIG_DYNLINK),y)
LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y

include $(BUILD_SERVICE)/svc-common.mk
