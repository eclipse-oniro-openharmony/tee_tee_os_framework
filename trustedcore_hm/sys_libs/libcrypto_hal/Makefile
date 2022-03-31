MODULE := libcrypto_hal${TARG}.a
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_ASCEND_SEC_ENABLE), true)
flags += -DASCEND_SEC_ENABLE
endif

ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
endif

ifeq ($(CONFIG_DRV_SEC_ENABLE), true)
flags += -DSEC_ENABLE
endif

ifeq ($(CONFIG_IPC_SEC_ENABLE), true)
flags += -DSEC_ENABLE
endif

ifeq ($(CONFIG_KUNPENG_SEC_ENABLE), true)
flags += -DSEC_ENABLE
endif

ifeq ($(CONFIG_CRYPTO_SUPPORT_DES),true)
c-flags += -DCRYPTO_SSL_SUPPORT_DES
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_EC25519),true)
c-flags += -DCRYPTO_SSL_SUPPORT_EC25519
endif

ifeq ($(CONFIG_CRYPTO_SUPPORT_MD5),true)
c-flags += -DCRYPTO_SSL_SUPPORT_MD5
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_SHA1),true)
c-flags += -DCRYPTO_SSL_SUPPORT_SHA1
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_SHA224),true)
c-flags += -DCRYPTO_SSL_SUPPORT_SHA224
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_3DES),true)
c-flags += -DCRYPTO_SSL_SUPPORT_3DES
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_UNSAFE_RSA),true)
c-flags += -DCRYPTO_SSL_SUPPORT_UNSAFE_RSA
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_UNSAFE_ECDSA),true)
c-flags += -DCRYPTO_SSL_SUPPORT_UNSAFE_ECDSA
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_UNSAFE_ECDH),true)
c-flags += -DCRYPTO_SSL_SUPPORT_UNSAFE_ECDH
endif
ifeq ($(CONFIG_CRYPTO_SUPPORT_UNSAFE_DH),true)
c-flags += -DCRYPTO_SSL_SUPPORT_UNSAFE_DH
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),boringssl)
c-flags += -DBORINGSSL_ENABLE
else
c-flags += -DOPENSSL_ENABLE
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
c-flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

inc-flags += -I$(TOPDIR)/drivers/base_mgr/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/gpapi # rpmb_fcntl.h
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/teeapi/common # tee_property_inner.h

inc-flags += -I$(PREBUILD_HEADER)/gmssl/openssl

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), boringssl)
inc-flags += -I$(PREBUILD_HEADER)/boringssl
else ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

# Source files required to build the target
libcrypto_hal_c_files += $(wildcard src/*.c) \
                         $(wildcard src/boringssl/*.c)

crypto_mgr_file = src/crypto_mgr_manager.c
crypto_file = src/crypto_manager.c

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
libcrypto_hal_c_files := $(filter-out $(crypto_file), $(libcrypto_hal_c_files))
else
libcrypto_hal_c_files := $(filter-out $(crypto_mgr_file), $(libcrypto_hal_c_files))
endif

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libcrypto_hal/include/*)

include $(TOPDIR)/mk/lib-common.mk
