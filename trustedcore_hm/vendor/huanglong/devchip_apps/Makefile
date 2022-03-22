
ifeq ($(CFG_HI_TEE_EXPORT_FLAG),)
TEE_DIR ?= $(shell cd $(CURDIR)/.. && /bin/pwd)
#include $(TEE_DIR)/secureos/itrustee/build/base.mk
endif

KEYMASTER_TA_DIR := $(shell ([ -d $(SDK_DIR)/../component/ta/keymaster ] && echo ../../../../component/ta/keymaster) || \
                            ([ -d $(SDK_DIR)/../modules/ta/keymaster ] && echo ../../../../modules/ta/keymaster) || \
                            ([ -d $(SDK_DIR)/../component/drm/ta/keymaster ] && echo ../../../../component/drm/ta/keymaster) || \
                            ([ -d $(SDK_DIR)/../hidolphin/component/ta/keymaster ] && echo ../../../../hidolphin/component/ta/keymaster) || \
                            ([ -d keymaster ] && echo 'keymaster') || \
                            echo '')
$(info KEYMASTER_TA_DIR = $(KEYMASTER_TA_DIR))
GATEKEEPER_TA_DIR := $(shell ([ -d $(SDK_DIR)/../component/ta/gatekeeper ] && echo ../../../../component/ta/gatekeeper) || \
                            ([ -d $(SDK_DIR)/../modules/ta/gatekeeper ] && echo ../../../../modules/ta/gatekeeper) || \
                            ([ -d $(SDK_DIR)/../component/drm/ta/gatekeeper ] && echo ../../../../component/drm/ta/gatekeeper) || \
                            ([ -d $(SDK_DIR)/../hidolphin/component/ta/gatekeeper ] && echo ../../../../hidolphin/component/ta/gatekeeper) || \
                            ([ -d gatekeeper ] && echo 'gatekeeper') || \
                            echo '')
$(info GATEKEEPER_TA_DIR = $(GATEKEEPER_TA_DIR))
CDRM_KEY_TA_DIR := $(shell ([ -d $(SDK_DIR)/../component/ta/cdrm_key ] && echo ../../../../component/ta/cdrm_key) || \
                            ([ -d $(SDK_DIR)/../modules/ta/cdrm_key ] && echo ../../../../modules/ta/cdrm_key) || \
                            ([ -d $(SDK_DIR)/../component/drm/ta/cdrm_key ] && echo ../../../../component/drm/ta/cdrm_key) || \
                            ([ -d $(SDK_DIR)/../hidolphin/component/ta/cdrm_key ] && echo ../../../../hidolphin/component/ta/cdrm_key) || \
                            ([ -d cdrm_key ] && echo 'cdrm_key') || \
                            echo '')
$(info CDRM_KEY_TA_DIR = $(CDRM_KEY_TA_DIR))
devchip_tadirs :=
devchip_tas :=
HI_TEE_API_DIR := $(TOPDIR)/vendor/huanglong/libdevchip_api
HI_TEE_TA_DIR := $(TOPDIR)/vendor/huanglong/devchip_apps

ifeq ($(strip $(CFG_HI_TEE_DEMO_SUPPORT)), y)
devchip_tadirs += demo
devchip_tas    += task_hisi_demo.elf
endif

ifeq ($(strip $(CFG_HI_TEE_KEYMASTER_SUPPORT)), y)
ifneq ($(KEYMASTER_TA_DIR), )
devchip_tadirs += $(KEYMASTER_TA_DIR)
devchip_tas += task_keymaster.elf
endif
endif

ifeq ($(strip $(CFG_HI_TEE_GATEKEEPER_SUPPORT)), y)
ifneq ($(GATEKEEPER_TA_DIR), )
devchip_tadirs += $(GATEKEEPER_TA_DIR)
devchip_tas += task_gatekeeper.elf
endif
endif

ifeq ($(strip $(CFG_HI_TEE_CHINADRM_KEY_SUPPORT)), y)
ifneq ($(CDRM_KEY_TA_DIR), )
devchip_tadirs += $(CDRM_KEY_TA_DIR)
devchip_tas += task_cdrm_key.elf
endif
endif

ifeq ($(strip $(CFG_HI_TEE_SSM_TEST_SUPPORT)), y)
devchip_tadirs += ssm_test
devchip_tas    += task_hisi_ssm_test.elf

devchip_tadirs += ssm_test_2
devchip_tas    += task_hisi_ssm_test_2.elf
endif

ifeq ($(strip $(CFG_HI_TEE_SSM_SUPPORT)), y)
devchip_tadirs += ssm
devchip_tas    += task_hisi_ssm.elf
endif

ifeq ($(strip $(CFG_HI_TEE_SMMU_SUPPORT)), y)
devchip_tadirs += smmu
devchip_tas    += smmu_task.elf
endif

ifeq ($(strip $(CFG_HI_TEE_COMMON_SUPPORT)), y)
devchip_tadirs += common
devchip_tas    += task_hisi_common.elf
endif

ifeq ($(strip $(CFG_HI_TEE_OTP_SUPPORT)), y)
devchip_tadirs += otp
devchip_tas    += task_hisi_otp.elf
endif

ifeq ($(strip $(CFG_HI_TEE_KLAD_SUPPORT)), y)
devchip_tadirs += klad
devchip_tas    += task_hisi_klad.elf
endif

ifeq ($(strip $(CFG_HI_TEE_HDMITX_SUPPORT)), y)
devchip_tadirs += hdmitx
devchip_tas    += task_hisi_hdmitx.elf
endif

ifeq ($(strip $(CFG_HI_TEE_KEYSLOT_SUPPORT)), y)
devchip_tadirs += keyslot
devchip_tas    += task_hisi_keyslot.elf
endif


ifeq ($(strip $(CFG_HI_TEE_DEMUX_SUPPORT)), y)
devchip_tadirs += demux
devchip_tas    += task_hisi_dmx.elf
endif

ifeq ($(strip $(CFG_HI_TEE_CIPHER_SUPPORT)), y)
#devchip_tadirs += cipher
devchip_tas    +=
endif

ifeq ($(strip $(CFG_HI_TEE_TEST_CIPHER_SUPPORT)), y)
devchip_tadirs += test_cipher
devchip_tas    += task_hisi_test_cipher.elf
endif

ifeq ($(strip $(CFG_HI_TEE_VFMW_SUPPORT)), y)
devchip_tadirs += vfmw
devchip_tas    += task_hisi_vfmw.elf
endif

ifeq ($(strip $(CFG_HI_TEE_PVR_SUPPORT)), y)
devchip_tadirs += pvr
devchip_tas    += task_hisi_pvr.elf
endif

ifeq ($(strip $(CFG_HI_TEE_HDMIRX_SUPPORT)), y)
devchip_tadirs += hdmirx
devchip_tas    += task_hisi_hdmirx.elf
endif

ifeq ($(strip $(CFG_HI_TEE_NPU_TEST_SUPPORT)), y)
devchip_tadirs += npu_test
devchip_tas    += task_hisi_npu_test.elf
endif

#ifeq ($(strip $()), y)
#devchip_tadirs +=
#devchip_tas    +=
#endif

