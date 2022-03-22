
MODULE := libnpu_v200.a

include $(TOPDIR)/mk/var.mk

#ifneq ($(chip_type),cs2)
#AP_PLAT_HEAD_PATH:= $(TOPDIR)/../../../../../vendor/hisi/ap/platform/kirin990
#else
#AP_PLAT_HEAD_PATH:= $(TOPDIR)/../../../../../vendor/hisi/ap/platform/kirin990_cs2
#endif

ifeq ($(chip_type), es)
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/include/platform/baltimore_es
else
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/include/platform/baltimore
endif

c-flags += -Wall -Wextra -w
c-flags += -DTEE_SUPPORT_SECISP

inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/uapi
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/inc
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/device
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/manager
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/platform
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/secmem/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/secsvm/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/npu_v200/platform/hi36a0
inc-flags += -I$(AP_PLAT_HEAD_PATH)

npu_v200_c_files += platform/hi36a0/npu_adapter.c
npu_v200_c_files += platform/npu_reg.c
ifneq ($(chip_type), es)
    npu_v200_c_files += platform/hi36a0/npu_chip_cfg.c
endif

npu_v200_c_files += device/npu_dev_ctx_mngr.c
npu_v200_c_files += device/npu_event_info_mngr.c
npu_v200_c_files += device/npu_hwts_driver.c
npu_v200_c_files += device/npu_hwts_sqe.c
npu_v200_c_files += device/npu_hwts_sq_mngr.c
npu_v200_c_files += device/npu_model_info_mngr.c
npu_v200_c_files += device/npu_pm.c
npu_v200_c_files += device/npu_proc_ctx_mngr.c
npu_v200_c_files += device/npu_schedule_task.c
npu_v200_c_files += device/npu_semaphore.c
npu_v200_c_files += device/npu_stream_info_mngr.c
npu_v200_c_files += device/npu_task_info_mngr.c
npu_v200_c_files += manager/npu_custom_ioctl_services.c
npu_v200_c_files += manager/npu_ioctl_services.c
npu_v200_c_files += manager/npu_manager.c


ifeq ($(chip_type),es)
    inc-flags += -DISP_CHIP_ES
endif
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/common/include
#inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/baltimore
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/include

include $(TOPDIR)/mk/lib-common.mk
