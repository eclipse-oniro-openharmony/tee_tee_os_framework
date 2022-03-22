#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += ../../api/include
drv_incs += ../../api/pvr

drv_incs += .
ifeq ($(strip $(CFG_HI_TEE_SMMU_SUPPORT)), y)
drv_flags += -DPVR_SMMU_SUPPORT
endif

drv_srcs += tee_drv_pvr_play.c \
            tee_drv_pvr.c

