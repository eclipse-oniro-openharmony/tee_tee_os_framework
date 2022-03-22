
drv_global_incdirs := include
drv_dirs :=

drv_dirs += os_hal/itrustee
drv_dirs += tzasc
drv_dirs += mem_layout
drv_dirs += mem

drv_dirs += license

ifeq ($(strip $(CFG_HI_TEE_LOG_SUPPORT)), y)
drv_dirs += common/log
endif

ifeq ($(strip $(CFG_HI_TEE_CIPHER_SUPPORT)), y)
drv_dirs += cipher
endif

ifeq ($(strip $(CFG_HI_TEE_DEMO_SUPPORT)), y)
drv_dirs += demo
endif

ifeq ($(strip $(CFG_HI_TEE_SSM_SUPPORT)), y)
drv_dirs += ssm
endif

ifeq ($(strip $(CFG_HI_TEE_OTP_SUPPORT)), y)
drv_dirs += otp
endif

ifeq ($(strip $(CFG_HI_TEE_KLAD_SUPPORT)), y)
drv_dirs += klad
endif

ifeq ($(strip $(CFG_HI_TEE_KEYSLOT_SUPPORT)), y)
drv_dirs += keyslot
endif

ifeq ($(strip $(CFG_HI_TEE_DEMUX_SUPPORT)), y)
drv_dirs += demux
endif

ifeq ($(strip $(CFG_HI_TEE_TSR2RCIPHER_SUPPORT)), y)
drv_dirs += tsr2rcipher
endif

ifeq ($(strip $(CFG_HI_TEE_PVR_SUPPORT)), y)
drv_dirs += pvr
endif

ifeq ($(strip $(CFG_HI_TEE_HDMITX_SUPPORT)), y)
drv_dirs += hdmitx
endif

ifeq ($(strip $(CFG_HI_TEE_HDMIRX_SUPPORT)), y)
drv_dirs += hdmirx
endif

ifeq ($(strip $(CFG_HI_TEE_VFMW_SUPPORT)), y)
drv_dirs += vfmw
endif

ifeq ($(strip $(CFG_HI_TEE_COMMON_SUPPORT)), y)
drv_dirs += common
endif

ifeq ($(strip $(CFG_HI_TEE_MAILBOX_SUPPORT)), y)
drv_dirs += mailbox
endif

ifeq ($(strip $(CFG_HI_TEE_DYNAMIC_TA_LOAD)), y)
drv_dirs += taload
endif

ifeq ($(strip $(CFG_HI_TEE_NPU_SUPPORT)), y)
drv_dirs += npu
endif
