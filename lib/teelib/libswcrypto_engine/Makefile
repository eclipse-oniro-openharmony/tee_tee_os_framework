#
# Copyright 2018, Huawei Co. Ltd.
#

MODULE := libswcrypto_engine${TARG}.a

c-flags += -DARM_PAE=1 -D__ARM_ARCH_=7 -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

inc-flags += -I$(TOPDIR)/sys_libs/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_shared/include
inc-flags += -I$(TOPDIR)/vendor/common/include # chip_info.h
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/gpapi
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/teeapi

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), mbedtls)
inc-flags += -I$(PREBUILD_HEADER)/mbedtls
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

libswcrypto_engine_c_files += $(wildcard src/*.c)
libswcrypto_engine_c_files += $(wildcard src/stub/*.c)

ifeq ($(CONFIG_CRYPTO_SUPPORT_X509),true)
c-flags += -DCRYPTO_SSL_SUPPORT_X509
libswcrypto_engine_c_files := $(filter-out src/stub/create_cert_wrapper_stub.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/stub/tee_ext_cert_api_stub.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/stub/x509_wrapper_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/create_cert_wrapper.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/tee_ext_cert_api.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/x509_wrapper.c, $(libswcrypto_engine_c_files))
endif

ifeq ($(CONFIG_CRYPTO_ECC_WRAPPER),true)
libswcrypto_engine_c_files := $(filter-out src/stub/ec_wrapper_stub.c, $(libswcrypto_engine_c_files))
ifeq ($(CONFIG_CRYPTO_SUPPORT_X509),true)
libswcrypto_engine_c_files := $(filter-out src/stub/ec_wrapper_x509_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper_x509.c, $(libswcrypto_engine_c_files))
endif
else
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper_x509.c, $(libswcrypto_engine_c_files))
endif

ifeq ($(CONFIG_CRYPTO_AES_WRAPPER),true)
libswcrypto_engine_c_files := $(filter-out src/stub/aes_wrapper_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/aes_wrapper.c, $(libswcrypto_engine_c_files))
endif

c-flags += -DOPENSSL_ENABLE
libswcrypto_engine_c_files := $(filter-out src/stub/rsa_wrapper_stub.c, $(libswcrypto_engine_c_files))

EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libswcrypto_engine/include/*)

include $(TOPDIR)/mk/lib-common.mk
