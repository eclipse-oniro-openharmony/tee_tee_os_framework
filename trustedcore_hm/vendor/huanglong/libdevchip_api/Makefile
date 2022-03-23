### api dir ###
api_dirs :=

api_dirs += ta_al/itrustee

api_dirs += mem

ifeq ($(strip $(CFG_HI_TEE_DYNAMIC_TA_LOAD)), y)
api_dirs += taload
flags += -DCFG_HI_TEE_DYNAMIC_TA_LOAD
endif

ifeq ($(strip $(CFG_HI_TEE_DEMO_SUPPORT)), y)
api_dirs += demo
flags += -DCFG_HI_TEE_DEMO_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_SSM_SUPPORT)), y)
api_dirs += ssm
flags += -DCFG_HI_TEE_SSM_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_COMMON_SUPPORT)), y)
api_dirs += common
flags += -DSOS_VERSION=0x0
flags += -DCFG_HI_TEE_COMMON_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_LOG_SUPPORT)), y)
api_dirs += common/log
flags += -DCFG_HI_TEE_LOG_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_DEMUX_SUPPORT)), y)
api_dirs += demux
flags += -DCFG_HI_TEE_DEMUX_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_OTP_SUPPORT)), y)
api_dirs += otp
#define CMD_OTP_PROCESS 0xF140
flags += -DCFG_HI_TEE_OTP_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_KLAD_SUPPORT)), y)
api_dirs += klad
flags += -DCFG_HI_TEE_KLAD_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_HDMITX_SUPPORT)), y)
api_dirs += hdmitx
flags += -DCFG_HI_TEE_HDMITX_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_KEYSLOT_SUPPORT)), y)
api_dirs += keyslot
flags += -DCFG_HI_TEE_KEYSLOT_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_CIPHER_SUPPORT)), y)
api_dirs += cipher
flags += -DCFG_HI_TEE_CIPHER_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_TSR2RCIPHER_SUPPORT)), y)
api_dirs += tsr2rcipher
flags += -DCFG_HI_TEE_TSR2RCIPHER_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_PVR_SUPPORT)), y)
api_dirs += pvr
flags += -DCFG_HI_TEE_PVR_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_HDMIRX_SUPPORT)), y)
api_dirs += hdmirx
flags += -DCFG_HI_TEE_HDMIRX_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_NPU_SUPPORT)), y)
api_dirs += npu
flags += -DCFG_HI_TEE_NPU_SUPPORT
endif

ifeq ($(strip $(CFG_HI_TEE_CHINADRM_HAL_SUPPORT)), y)
CHINADRM_DIR = $(HI_TEE_API_DIR)/cdrm_hal
CHINADRM_EXIST = $(shell test ! -e $(CHINADRM_DIR) || echo "true")
ifeq ($(CHINADRM_EXIST), true)
api_dirs += cdrm_hal
endif
endif

ifeq ($(strip $(CFG_TEE_RPMB_SUPPORT)), y)
api_dirs += flash
flags += -DCFG_TEE_RPMB_SUPPORT
endif

##########################################################################
# DULE is a lib
MODULE := libdevchip_api$(TARG).a

### flags ###
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)

c-flags += -Wno-unused-parameter
c-flags += -fno-builtin
c-flags += -Wall -Wextra

inc-flags += -I$(TOPDIR)/vendor/huanglong/libdevchip_api/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/include
inc-flags += -I$(TOPDIR)/platform/huanglong/ta_load
inc-flags += -I$(TOPDIR)/drivers/platdrv/include

ifeq ($(CFG_ADVCA_NAGRA),y)
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/
endif

EXPORT_HDRS += $(wildcard include/*)
EXPORT_HDRS += ta_al/itrustee/hi_tee_hal.h

### src ###
define eval_apis
api_incs  :=
api_srcs  :=
api_flags :=

include $$(TOPDIR)/vendor/huanglong/libdevchip_api/$(1)/Makefile

$(1)_api_incs  := $$(addprefix -I$$(TOPDIR)/vendor/huanglong/libdevchip_api/$(1)/, $$(api_incs))
$(1)_api_srcs  := $$(addprefix $(1)/, $$(api_srcs))
$(1)_api_flags := $$(api_flags)

inc-flags   += $$($(1)_api_incs)
inc-flags   += $$($(1)_api_flags)
api_c_files += $$($(1)_api_srcs)
endef

$(foreach module, $(api_dirs), $(eval $(call eval_apis,$(module))))

libdevchip_api_c_files := $(api_c_files)

include $(TOPDIR)/mk/lib-common.mk

