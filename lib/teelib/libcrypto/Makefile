#
# Copyright 2019, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
TARGETS := libcrypto${TARG}.a

include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

CPPFLAGS += -I$(PWD)/libs/teelib/libcrypto/include
CPPFLAGS += -I$(PWD)/libs/teelib/libssa/include
CPPFLAGS += -I$(PWD)/libs/syslib/libteemem/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/src
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/libs/libcrypto_common
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(PWD)/libs/teelib/libelf_verify/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include # msg_ops.h

CFILES   := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))

CFILES   := $(filter-out src/tee_crypto_signature_verify_mbedtls.c, $(CFILES))

ifeq ($(GP_SUPPORT), y)
CFILES := $(filter-out src/tee_crypto_api_hash.c, $(CFILES))
CFILES := $(filter-out src/tee_crypto_api_hmac.c, $(CFILES))
else
CFILES := $(filter-out src/tee_crypto_gp_hash.c, $(CFILES))
CFILES := $(filter-out src/tee_crypto_gp_hmac.c, $(CFILES))
endif

#32M when ascend, others 500K
CFLAGS += -DMAX_SRC_SIZE=512000
A32_CFLAGS += -DMAX_SRC_SIZE=512000

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
CFLAGS += -DOPENSSL_ENABLE
A32_CFLAGS += -DOPENSSL_ENABLE
CPPFLAGS += -I$(PWD)/libs/teelib/libopenssl/openssl/include
CPPFLAGS += -I$(PWD)/libs/teelib/libopenssl/openssl/crypto
CPPFLAGS += -I$(PWD)/../tee_os_framework/open_source/OpenSSL/include
CPPFLAGS += -I$(PWD)/../tee_os_framework/open_source/OpenSSL/crypto
CPPFLAGS += -I$(PWD)/../tee_os_framework/open_source/OpenSSL/crypto/include
endif

ifeq (${TARG}, _a32)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/arm/*.S))
endif

ifeq (${TARG}, )
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/aarch64/*.S))
endif

include $(HM_COMMON)/common.mk
