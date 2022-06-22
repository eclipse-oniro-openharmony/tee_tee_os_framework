MODULE := libcrypto_hal${TARG}.a
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_CRYPTO_SUPPORT_EC25519),true)
c-flags += -DCRYPTO_SSL_SUPPORT_EC25519
endif

c-flags += -DOPENSSL_ENABLE

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
c-flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

ifeq ($(CONFIG_CIPHER_ENABLE), true)
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
