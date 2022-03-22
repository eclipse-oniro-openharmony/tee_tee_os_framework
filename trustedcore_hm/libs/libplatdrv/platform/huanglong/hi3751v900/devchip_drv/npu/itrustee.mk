#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += ../../api/include
drv_incs += ../../api/npu
drv_incs += ../../api/npu/include

#ifeq ($(strip $(CFG_HI_TEE_NPU_SMMU_SUPPORT)), y)
#drv_flags += -DNPU_SMMU_SUPPORT
#endif

drv_srcs += tee_drv_npu_intf.c \
						tee_drv_npu_func.c \
						tee_drv_npu_utils.c \
						tee_drv_npu_pm.c \
						tee_drv_npu_test_hwts.c
