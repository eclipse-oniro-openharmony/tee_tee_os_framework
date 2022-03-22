ifeq ($(CONFIG_PRIVACY_PROTECTION), true)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/privacy_protection
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/msp_engine/include
#inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common
#inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/pal
inc-flags += -DCONFIG_PRIVACY_PROTECTION
CFILES += platform/libthirdparty_drv/plat_drv/privacy_protection/privacy_protection_common.c \
          platform/libthirdparty_drv/plat_drv/privacy_protection/privacy_protection_syscall.c
endif
