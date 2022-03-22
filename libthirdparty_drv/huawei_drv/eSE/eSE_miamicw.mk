# general_se
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -DCONFIG_ESE_TEE2ATF_LOCK
#inc-flags += -DCONFIG_ESE_EXCLUDE_P61
#inc-flags += -DSE_VENDOR_GENERAL_SEE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/hisee
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/t1
inc-flags += -I$(SOURCE_DIR)/platform/common/
CFILES += \
    platform/libthirdparty_drv/huawei_drv/eSE/se_dummy.c \
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/hisee.c \
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ese_data_handle.c \
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_a.c \
    platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_msg.c

inc-flags += -DSE_SUPPORT_ST
inc-flags += -DSE_VENDOR_NXP
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/t1/t1.c
CFILES += platform/libthirdparty_drv/huawei_drv/eSE/p61/p61.c
