ifeq ($(TARGET_BOARD_PLATFORM), kirin990)
ifneq ($(chip_type),cs2)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/kirin990
else
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/kirin990_cs2
endif
endif
ifeq ($(TARGET_BOARD_PLATFORM), denver)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/denver
endif
ifeq ($(TARGET_BOARD_PLATFORM), orlando)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/orlando
endif
ifeq ($(TARGET_BOARD_PLATFORM), laguna)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/orlando
endif
ifeq ($(TARGET_BOARD_PLATFORM), burbank)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/burbank
endif


NPU_DRIVER_INC_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/npu/inc/driver

inc-flags += -DTEE_SUPPORT_NPU
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/uapi
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/inc
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/comm
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/device/common
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/device/resource
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/manager
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/

#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/include
ifeq ($(TARGET_BOARD_PLATFORM), kirin990)
ifneq ($(chip_type),cs2)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi3690
else
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2
endif
endif
ifeq ($(TARGET_BOARD_PLATFORM), denver)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6290
endif
ifeq ($(TARGET_BOARD_PLATFORM), orlando)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6280
endif
ifeq ($(TARGET_BOARD_PLATFORM), laguna)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6285
endif
ifeq ($(TARGET_BOARD_PLATFORM), burbank)
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6286
endif

inc-flags += -I$(AP_PLAT_HEAD_PATH)
inc-flags += -I$(NPU_DRIVER_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

#npu kernel driver
#platform module
ifeq ($(TARGET_BOARD_PLATFORM), kirin990)
ifneq ($(chip_type),cs2)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi3690/npu_adapter.c
else
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2/npu_adapter.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/kirin990_cs2/npu_chip_cfg.c
endif
endif
ifeq ($(TARGET_BOARD_PLATFORM), denver)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6290/npu_adapter.c
endif
ifeq ($(TARGET_BOARD_PLATFORM), orlando)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6280/npu_adapter.c
endif
ifeq ($(TARGET_BOARD_PLATFORM), laguna)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6285/npu_adapter.c
endif
ifeq ($(TARGET_BOARD_PLATFORM), burbank)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/hi6286/npu_adapter.c
endif
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_irq.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_reg.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_dfx.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_gic.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_resmem.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_feature.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/platform/npu_platform.c

#device common module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_common.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_cma.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_shm.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_mailbox_msg.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_doorbell.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_pm.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/common/npu_devinit.c

#device resource module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_mailbox.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_mailbox_utils.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_calc_sq.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_calc_cq.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_stream.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_sink_stream.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_event.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_model.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_task.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/resource/npu_semaphore.c

#device service module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/device/service/npu_calc_channel.c

#manager module
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/device/service
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v100/inc
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_proc_ctx.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_ioctl_services.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager_ioctl_services.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_recycle.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager_common.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v100/manager/npu_manager.c

