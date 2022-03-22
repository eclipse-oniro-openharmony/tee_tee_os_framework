# general_se
inc-flags += -DSE_VENDOR_GENERAL_SEE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/hisee
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/huawei_drv/eSE/p61
CFILES += \
          platform/libthirdparty_drv/huawei_drv/eSE/se_dummy.c \
          platform/libthirdparty_drv/huawei_drv/eSE/hisee/hisee.c \
          platform/libthirdparty_drv/huawei_drv/eSE/hisee/ese_data_handle.c \
          platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_a.c \
          platform/libthirdparty_drv/huawei_drv/eSE/hisee/ipc_msg.c

# p61
inc-flags += -DSE_VENDOR_NXP
CFILES += platform/kirin/eSE/p61/p61.c
