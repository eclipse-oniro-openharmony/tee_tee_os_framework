# general_se
ifneq ($(product_range),base)
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/hisee
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/hisee/ese_data_handle.c
endif

# p73
inc-flags += -DPLATFORM_NO_GENERAL_SEE_FLAG
inc-flags += -DSE_VENDOR_NXP
inc-flags += -DHISI_TEE
inc-flags += -DSE_SUPPORT_MULTISE
inc-flags += -DSE_SUPPORT_SN110
inc-flags += -DSE_SUPPORT_ST
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61/inc
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61/lib
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/t1
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/inc
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/pal
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/common
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/lib
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/spm
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/utils
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/spi

CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/p61.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEse_Api_p61.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEse_Api_hisi_p61.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEseDataMgr_p61.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/lib/phNxpEseProto7816_3_p61.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/t1/t1.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/p73.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/spi/phNxpEsePal_spi.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/pal/phNxpEsePal.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Api.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Api_hisi.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEse_Apdu_Api.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEseDataMgr.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/lib/phNxpEseProto7816_3.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/utils/ese_config_hisi.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p73/utils/ringbuffer.c


