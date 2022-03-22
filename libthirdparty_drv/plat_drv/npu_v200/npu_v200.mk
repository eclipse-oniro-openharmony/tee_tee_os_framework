
#NPU //baltimore enable compile
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/uapi
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/inc
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/device
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/manager
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/platform

#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu_v200/platform/hi36a0
inc-flags += -I$(AP_PLAT_HEAD_PATH)
#inc-flags += -I$(NPU_DRIVER_INC_PATH):
#inc-flags += -I$(NPU_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

#npu kernel driver
#platform module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/platform/hi36a0/npu_adapter.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/platform/npu_reg.c
ifneq ($(chip_type), es)
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/platform/hi36a0/npu_chip_cfg.c
endif
#device resource module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_dev_ctx_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_event_info_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_hwts_driver.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_hwts_sqe.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_hwts_sq_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_model_info_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_pm.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_proc_ctx_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_schedule_task.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_semaphore.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_stream_info_mngr.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/device/npu_task_info_mngr.c

#manager module
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/manager/npu_custom_ioctl_services.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/manager/npu_ioctl_services.c
CFILES += platform/libthirdparty_drv/plat_drv/npu_v200/manager/npu_manager.c
