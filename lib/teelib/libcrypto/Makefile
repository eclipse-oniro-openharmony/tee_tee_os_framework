#
# Copyright 2019, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libcrypto${TARG}.a

CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/src
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TOPDIR)/libs/libcrypto_common
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteemem/include

CFILES   := $(wildcard src/*.c)

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
CPPFLAGS += -I$(TOPDIR)/../open_source/OpenSSL/include
CPPFLAGS += -I$(TOPDIR)/../open_source/OpenSSL/crypto
CPPFLAGS += -I$(TOPDIR)/../open_source/OpenSSL/crypto/include
endif

ifeq (${TARG}, _a32)
ASMFILES += $(wildcard src/arm/*.S)
endif

ifeq (${TARG}, )
ASMFILES += $(wildcard src/aarch64/*.S)
endif

include $(TOPDIR)/mk/lib-common.mk
