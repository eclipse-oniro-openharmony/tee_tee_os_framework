MODULE := libcrypto_hal${TARG}.a
include $(TOPDIR)/mk/feature-macro.mk

ifeq ($(CONFIG_CRYPTO_SUPPORT_EC25519),true)
c-flags += -DCRYPTO_SSL_SUPPORT_EC25519
endif

c-flags += -DOPENSSL_ENABLE

ifneq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), )
c-flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include
inc-flags += -I$(TEELIB)/libhmdrv/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/gpapi
inc-flags += -I$(PREBUILD_HEADER)/inner_sdk/teeapi/common # tee_property_inner.h

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

# Source files required to build the target
libcrypto_hal_c_files += $(wildcard src/*.c) \
                         $(wildcard src/boringssl/*.c)

include $(TOPDIR)/mk/lib-common.mk
