#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

ifeq ($(strip $(CFG_HI_TEE_SMMU_SUPPORT)), y)
drv_flags += -DTSR2RCIPHER_SMMU_SUPPORT
endif

drv_flags += -DLOG_MODULE_ID=HI_ID_TSR2RCIPHER

drv_incs += .
drv_srcs += tee_drv_tsr2rcipher_intf.c \
            tee_drv_tsr2rcipher.c \
            tee_drv_tsr2rcipher_func.c \
            tee_hal_tsr2rcipher.c
