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

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
c-flags += -DMBEDTLS_ENABLE
else
c-flags += -DOPENSSL_ENABLE
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
c-flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

ifeq ($(CONFIG_CIPHER_ENABLE), true)
flags += -DDX_ENABLE=1
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/src/cclib
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/pal/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/crys
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include
endif

inc-flags += -I$(TOPDIR)/drivers/base_mgr/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/cdrmr
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/pal
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/adapter
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/gpapi
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/teeapi/common # tee_property_inner.h

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
else
inc-flags += -I$(PREBUILD_HEADER)/mbedtls
endif

# Source files required to build the target
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
c-flags += -DMBEDTLS_ENABLE
libcrypto_hal_c_files += src/crypto_alg_config.c \
                         src/crypto_hal.c        \
                         src/crypto_hal_ae.c     \
                         src/crypto_hal_cipher.c \
                         src/crypto_hal_derive_key.c \
                         src/crypto_hal_ec.c     \
                         src/crypto_hal_hash.c   \
                         src/crypto_hal_hmac.c   \
                         src/crypto_hal_rsa.c    \
                         src/crypto_manager.c    \
                         $(wildcard src/mbedtls/*.c)
else
libcrypto_hal_c_files += $(wildcard src/*.c) \
                         $(wildcard src/boringssl/*.c)
endif

ifeq ($(CONFIG_CIPHER_ENABLE), true)
libcrypto_hal_c_files += src/crypto_ext_api.c
libcrypto_hal_c_files := $(filter-out src/crypto_ext_api_stub.c, $(libcrypto_hal_c_files))
libcrypto_hal_c_files := $(filter-out src/tee_chinadrm_gmssl_api_stub.c, $(libcrypto_hal_c_files))
else
libcrypto_hal_c_files += src/crypto_ext_api_stub.c
libcrypto_hal_c_files := $(filter-out src/crypto_ext_api.c, $(libcrypto_hal_c_files))
libcrypto_hal_c_files := $(filter-out src/tee_chinadrm_gmssl_api.c, $(libcrypto_hal_c_files))
endif

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
