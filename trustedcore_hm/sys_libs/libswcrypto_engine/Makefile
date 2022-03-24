#
# Copyright 2018, Huawei Co. Ltd.
#

MODULE := libswcrypto_engine${TARG}.a

c-flags += -DARM_PAE=1 -D__ARM_ARCH_=7 -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

inc-flags += -I$(TOPDIR)/sys_libs/libswcrypto_engine/include
inc-flags += -I$(TOPDIR)/sys_libs/libcrypto_hal/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_shared/include
inc-flags += -I$(TOPDIR)/vendor/common/include # chip_info.h
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/gpapi # rpmb_fcntl.h
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/teeapi
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/common/crypto

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), boringssl)
inc-flags += -I$(PREBUILD_HEADER)/boringssl
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

libswcrypto_engine_c_files += $(wildcard src/*.c)

ifeq ($(CONFIG_CRYPTO_SUPPORT_X509),true)
c-flags += -DCRYPTO_SSL_SUPPORT_X509
endif

ifeq ($(CONFIG_CRYPTO_ECC_WRAPPER),true)
c-flags += -DCRYPTO_SUPPORT_ECC_WRAPPER
endif

ifeq ($(CONFIG_CRYPTO_AES_WRAPPER),true)
c-flags += -DCRYPTO_SUPPORT_AES_WRAPPER
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),boringssl)
c-flags += -DBORINGSSL_ENABLE
else
c-flags += -DOPENSSL_ENABLE
endif

EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libswcrypto_engine/include/*)

include $(TOPDIR)/mk/lib-common.mk
