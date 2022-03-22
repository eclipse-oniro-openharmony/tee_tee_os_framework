#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

TZASC_VERSION := v400

drv_incs += include \
            hal/include \
            hal/$(TZASC_VERSION)

drv_srcs += hi_tee_drv_tzasc.c \
            tee_drv_tzasc_common.c \
            hal/$(TZASC_VERSION)/tee_drv_tzasc_$(TZASC_VERSION).c


ifeq ($(strip $(CFG_HI_TEE_DEBUG_SUPPORT)), y)
drv_flags += -DTEE_DRV_TZASC_DEBUG
endif

