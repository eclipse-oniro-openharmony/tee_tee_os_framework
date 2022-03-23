# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
             -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot \
             -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include \
             -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/modem/include \
             -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secureboot/include

inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/include \
             -I$(SOURCE_DIR)/platform/common/include/ivp

inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2

ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

CFILES += platform/libthirdparty_drv/plat_drv/secureboot/secureboot_v2.c \
          platform/libthirdparty_drv/plat_drv/secureboot/secboot.c \
          platform/libthirdparty_drv/plat_drv/secureboot/cc_stub.c \
          platform/libthirdparty_drv/plat_drv/secureboot/process_hifi_info.c

CFILES  +=  \
          platform/libthirdparty_drv/plat_drv/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE
