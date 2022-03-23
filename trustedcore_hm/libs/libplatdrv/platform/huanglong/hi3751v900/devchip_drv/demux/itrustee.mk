#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += ../../api/include
drv_incs += ../../api/demux

ifeq ($(strip $(CFG_HI_TEE_SMMU_SUPPORT)), y)
drv_flags += -DDMX_SMMU_SUPPORT
endif

drv_srcs += tee_drv_demux.c \
            tee_drv_demux_utils.c \
            tee_drv_demux_intf.c \
            tee_drv_demux_func.c \
            tee_hal_demux.c \
            tee_drv_demux_index.c

