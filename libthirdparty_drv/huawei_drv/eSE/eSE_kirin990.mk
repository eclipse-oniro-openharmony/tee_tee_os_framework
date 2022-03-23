# general_se
inc-flags += -DSE_VENDOR_GENERAL_SEE
# I2C ESE open in kirin990
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -DCONFIG_GENERAL_SEE_IPC_SUPPORT_BIGDATA
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/hisee
CFILES += \
		  platform/libthirdparty_drv/huawei_drv/eSE/se_dummy.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/hisee/hisee.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/hisee/ese_data_handle.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_a.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_msg.c

ifeq ($(CONFIG_HISI_SECFLASH), true)
inc-flags += -DCONFIG_SECFLASH
inc-flags += -DSECFLASH_TEE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/secflash
CFILES += \
		  platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_data_link.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_io.c \
		  platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_timer.c
CONFIG_SECFLASH_DATA_LINK_TEST := false
ifeq ($(CONFIG_SECFLASH_DATA_LINK_TEST), true)
inc-flags += -DSECFLASH_DATA_LINK_TEST
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_test
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/secflash/secflash_data_link_test.c
endif
endif

# p61
inc-flags += -DSE_SUPPORT_ST
inc-flags += -DSE_VENDOR_NXP
inc-flags += -DHISI_TEE
inc-flags += -DSE_SUPPORT_MULTISE
inc-flags += -DSE_SUPPORT_SN110
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


