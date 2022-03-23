#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += .

drv_srcs += tee_drv_mem_layout.c

ifeq ($(strip $(CFG_HI_TEE_DEBUG_SUPPORT)), y)
drv_flags += -DTEE_DRV_MEM_LAYOUT_DEBUG
endif
