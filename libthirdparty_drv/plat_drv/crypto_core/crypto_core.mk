ifeq ($(CONFIG_CRYPTO_CORE), true)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE \
    -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61 \
    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_core \
    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_core/apdu \
    -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_core/test \

inc-flags += -DCRYPTO_EXT_TPDU \
    -DPLATFORM_NO_GENERAL_SEE_FLAG \
    -DCONFIG_CRYPTO_CORE \

CFILES += platform/libthirdparty_drv/huawei_drv/eSE/se_dummy.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/crypto_core.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/crypto_core_ipc.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/crypto_core_power.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/crypto_core_api.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/apdu/mspc_tpdu.c

ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DCRYPTO_CORE_DRIVER_TEST
CFILES += platform/libthirdparty_drv/plat_drv/crypto_core/test/crypto_core_test.c \
    platform/libthirdparty_drv/plat_drv/crypto_core/test/crypto_core_test_performance.c

ifeq ($(CONFIG_CRYPTO_CORE_IPC_TEST), true)
inc-flags += -DCONFIG_CRYPTO_CORE_IPC_TEST
CFILES += platform/libthirdparty_drv/plat_drv/crypto_core/test/crypto_core_ipc_test.c
endif #CONFIG_CRYPTO_CORE_IPC_TEST

endif #TARGET_BUILD_VARIANT
endif #CONFIG_CRYPTO_CORE

