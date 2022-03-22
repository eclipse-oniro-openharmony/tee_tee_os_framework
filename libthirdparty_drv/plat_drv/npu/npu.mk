#NPU //hi3680 enable compile
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/npu
CFILES += platform/libthirdparty_drv/plat_drv/npu/npu_main_sec.c  \
                  platform/libthirdparty_drv/plat_drv/npu/npu_smmu_sec.c   \
                  platform/libthirdparty_drv/plat_drv/npu/npu_task_sec.c    \
                  platform/libthirdparty_drv/plat_drv/npu/npu_task_sswq_sec.c  \
                  platform/libthirdparty_drv/plat_drv/npu/npu_task_wq_sec.c

