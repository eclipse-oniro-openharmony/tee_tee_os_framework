# baltimore
# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include

ifeq ($(chip_type), es)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/baltimore_es
else
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/baltimore
endif

#NPU //baltimore enable compile
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/uapi
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/device
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/manager
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/platform

#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/platform/hi36a0
inc-flags += -I$(AP_PLAT_HEAD_PATH)
#inc-flags += -I$(NPU_DRIVER_INC_PATH)
#inc-flags += -I$(NPU_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

#npu kernel driver
#platform module
CFILES += platform/kirin/npu_v200/platform/hi36a0/npu_adapter.c
CFILES += platform/kirin/npu_v200/platform/npu_reg.c
ifneq ($(chip_type), es)
CFILES += platform/kirin/npu_v200/platform/hi36a0/npu_chip_cfg.c
endif
#device resource module
CFILES += platform/kirin/npu_v200/device/npu_dev_ctx_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_event_info_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_hwts_driver.c
CFILES += platform/kirin/npu_v200/device/npu_hwts_sqe.c
CFILES += platform/kirin/npu_v200/device/npu_hwts_sq_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_model_info_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_pm.c
CFILES += platform/kirin/npu_v200/device/npu_proc_ctx_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_schedule_task.c
CFILES += platform/kirin/npu_v200/device/npu_semaphore.c
CFILES += platform/kirin/npu_v200/device/npu_stream_info_mngr.c
CFILES += platform/kirin/npu_v200/device/npu_task_info_mngr.c

#manager module
CFILES += platform/kirin/npu_v200/manager/npu_custom_ioctl_services.c
CFILES += platform/kirin/npu_v200/manager/npu_ioctl_services.c
CFILES += platform/kirin/npu_v200/manager/npu_manager.c

#socp
inc-flags += -DMODEM_SOCP_3_0
# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# spi i2c i3 test
ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/driver_test
inc-flags += -I$(SOURCE_DIR)/platform/kirin/spi
CFILES += platform/kirin/driver_test/i2c_test.c
CFILES += platform/kirin/driver_test/i3c_test.c
CFILES += platform/kirin/driver_test/spi_test.c
CFILES += platform/kirin/driver_test/bus_test.c
endif

# i2c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i2c
CFILES += platform/kirin/i2c/i2c.c

# I3C
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i3c
CFILES += platform/kirin/i3c/i3c.c

# spi
CFILES += platform/kirin/spi/spi.c

#ipc_mailbox
inc-flags += -DCONFIG_HISI_MAILBOX
inc-flags += -I$(SOURCE_DIR)/platform/common/include/mailbox
CFILES += platform/kirin/mailbox/ipc_mailbox.c

# gpio
CFILES += platform/kirin/gpio/gpio.c

# dma
inc-flags += -DCONFIG_SUPPORT_DMA_STATIC_ADDR
inc-flags += -DCONFIG_SUPPORT_DMA_MOD_QOS_LEVEL
CFILES += platform/kirin/dma/dma.c

# tzpc
inc-flags += -I$(SOURCE_DIR)/platform/common/tzpc
CFILES += platform/common/tzpc/tzpc_cfg.c

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

# oemkey
ifneq ($(product_range),base)
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk
endif

# secmem
# TEE_SUPPORT_TZMP2 must be true
inc-flags += -DTEE_SUPPORT_TZMP2
inc-flags += -DCONFIG_HISI_SION_RECYCLE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/include
CFILES += platform/kirin/secmem/driver/sion/sion.c \
	  platform/kirin/secmem/driver/iommu/siommu.c \
	  platform/kirin/secmem/driver/lib/genalloc.c \
	  platform/kirin/secmem/driver/lib/bitmap.c \
	  platform/kirin/secmem/driver/sion/sion_recycling.c

#
# Software workaround for baltimore SoC WE func.
# When SoC support WE and L3 exlusive, we may need it
#
inc-flags += -DCONFIG_SOC_WE_WORKAROUND

ifeq ($(WITH_ENG_VERSION), true)
CFILES += platform/kirin/secmem/driver/sion/sion_test.c
endif

# secmmuv3
ifeq ($(WITH_ENG_VERSION),true)
inc-flags += -DTEE_SMMUV3_DEBUG
endif
inc-flags += -DTEE_SUPPORT_SMMUV3
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/include
CFILES += platform/kirin/secmem/driver/iommu/sec_smmuv3.c

# secmem_ddr
COMPILE_SEC_DDR_TEST := false
inc-flags += -DDDR_FOUR_CHANNEL
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_CA_RD
inc-flags += -DDDR_CA_RD_PRINT
CFILES += platform/kirin/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/kirin/secmem/driver/sec/baltimore_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/baltimore/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/baltimore/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
CFILES += platform/kirin/secmem/driver/sec/kirin990/sec_region_test.c
inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif

# isp
inc-flags += -DTEE_SUPPORT_SECISP
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/baltimore
CFILES += platform/kirin/isp/hisp_mem.c
CFILES += platform/kirin/isp/hisp_load.c
CFILES += platform/kirin/isp/hisp_secboot.c
CFILES += platform/kirin/isp/baltimore/hisp_pwr.c
CFILES += platform/kirin/isp/baltimore/hisp.c
ifeq ($(chip_type),es)
inc-flags += -DISP_CHIP_ES
endif

# ivp
inc-flags += -DSEC_IVP
inc-flags += -DIVP_DUAL_CORE
inc-flags += -DCHECK_DDR_SEC_CONFIG
inc-flags += -I$(SOURCE_DIR)/platform/common/include/ivp
CFILES += platform/kirin/ivp/hivp.c
CFILES += platform/kirin/ivp/hivp_secboot.c

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO
# inc-flags += -DCONFIG_CHECK_OEM_INFO


inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

# use for baltimore and later platform
inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2
ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

CFILES += platform/kirin/secureboot/secureboot_v2.c \
	  platform/kirin/secureboot/secboot.c \
	  platform/kirin/secureboot/process_hifi_info.c

CFILES  +=  \
          platform/kirin/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE

inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/ \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include/bsdiff
platdrv_cpp_files += platform/kirin/secureboot/bspatch/bspatch.cpp \
	  platform/kirin/secureboot/bspatch/buffer_file.cpp \
	  platform/kirin/secureboot/bspatch/extents.cpp \
	  platform/kirin/secureboot/bspatch/extents_file.cpp \
	  platform/kirin/secureboot/bspatch/file.cpp \
	  platform/kirin/secureboot/bspatch/memory_file.cpp \
	  platform/kirin/secureboot/bspatch/sink_file.cpp \
	  platform/kirin/secureboot/bspatch/secure_bspatch.cpp

# hifi
inc-flags += -DCONFIG_SUPPORT_HIFI_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/hifi
CFILES += platform/kirin/hifi/hifi_reload.c

# hdcp for wifidisplay(wfd)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/hdcp_wfd
CFILES += platform/kirin/hdcp_wfd/hdcp_wfd.c

# libfdt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/libfdt/include
CFILES += platform/kirin/libfdt/acpi.c \
		  platform/kirin/libfdt/fdt.c \
		  platform/kirin/libfdt/fdt_addresses.c \
		  platform/kirin/libfdt/fdt_empty_tree.c \
		  platform/kirin/libfdt/fdt_overlay.c \
		  platform/kirin/libfdt/fdt_ro.c \
		  platform/kirin/libfdt/fdt_rw.c \
		  platform/kirin/libfdt/fdt_strerror.c \
		  platform/kirin/libfdt/fdt_sw.c \
		  platform/kirin/libfdt/fdt_wip.c \
		  platform/kirin/libfdt/fdt_handler.c

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c \
		  platform/kirin/ccdriver_lib/cc_adapt.c \
		  platform/kirin/ccdriver_lib/cc_power.c \
		  platform/kirin/ccdriver_lib/eps_adapt.c \
		  platform/common/cc_driver/cc_driver_hal.c
# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
inc-flags += -I$(SOURCE_DIR)/platform/common/display2.0 \
             -I$(SOURCE_DIR)/platform/common/display2.0/hdcp
CFILES += platform/common/display2.0/hisi_disp.c \
          platform/common/display2.0/hisi_fb_sec.c \
          platform/common/display2.0/hisi_overlay_utils.c \
          platform/common/display2.0/hisi_dss_module_registe.c \
		  platform/common/display2.0/hdcp_syscall.c

# Mate10 related sources "WITH_CHIP_HI3570"
CFILES += platform/common/display2.0/reg_dfc/hisi_dss_dfc_kirin980_base.c \
          platform/common/display2.0/reg_dma/hisi_dss_dma_kirin980_base.c \
          platform/common/display2.0/reg_ldi/hisi_dss_ldi_kirin990_base.c \
          platform/common/display2.0/reg_mctl/hisi_dss_mctl_kirin980_base.c \
          platform/common/display2.0/reg_mif/hisi_dss_mif_kirin9a0_base.c \
          platform/common/display2.0/reg_mix/hisi_dss_mix_kirin980_base.c \
          platform/common/display2.0/reg_ovl/hisi_dss_ovl_kirin980_base.c \
          platform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin980_base.c \
          platform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin9a0.c \
          platform/common/display2.0/channel_data/hisi_dss_channel_data_kirin9a0_base.c \
          platform/common/display2.0/hdcp/hisi_hdcp_common.c \
          platform/common/display2.0/hdcp/hisi_hdcp_soft.c \
          platform/common/display2.0/hdcp/hisi_hdcp_dp.c
inc-flags += -DCONFIG_DSS_TYPE_BALTIMORE

# touchscheen
inc-flags += -I$(SOURCE_DIR)/platform/common/touchscreen		\
	    -I$(SOURCE_DIR)/platform/common/touchscreen/panel	\
	    -I$(SOURCE_DIR)/platform/kirin/touchscreen
CFILES += \
      platform/common/touchscreen/hisi_tui_touchscreen.c	\
	  platform/common/touchscreen/panel/tui_amtel.c		\
	  platform/common/touchscreen/panel/tui_jdi.c		\
	  platform/common/touchscreen/panel/tui_novatek.c	\
	  platform/common/touchscreen/panel/tui_himax.c	\
	  platform/common/touchscreen/panel/tui_parade.c	\
	  platform/common/touchscreen/panel/tui_st.c		\
	  platform/common/touchscreen/panel/tui_st_new.c	\
	  platform/common/touchscreen/panel/tui_sec.c		\
	  platform/common/touchscreen/panel/tui_synaptics.c	\
	  platform/common/touchscreen/panel/tui_synaptics_tcm.c	\
	  platform/common/touchscreen/panel/tui_fts.c		\
	  platform/common/touchscreen/panel/tui_gt1x.c		\
	  platform/common/touchscreen/panel/tui_gtx8.c		\
	  platform/common/touchscreen/panel/tui_ssl.c		\
	  platform/common/touchscreen/panel/tui_elan.c

inc-flags += -I$(SOURCE_DIR)/platform/common
CFILES += $(wildcard platform/common/tui_drv/*.c)

# fingerprint
CFILES += platform/kirin/fingerprint/src/tee_fingerprint.c

#ese
ifneq ($(product_range),base)
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/hisee
CFILES += \
		  platform/kirin/eSE/hisee/ese_data_handle.c
endif

# Encrypted Image Incremental Update Service(eiius)
inc-flags += -DCONFIG_HISI_EIIUS
CFILES += platform/kirin/secureboot/eiius_interface.c

# file encry
inc-flags += -DCONFIG_FBE_UFS_KEY_WORKAROUND
inc-flags += -I$(SOURCE_DIR)/platform/kirin/file_encry_v3
CFILES += \
		  platform/kirin/file_encry_v3/sec_fbe3_ufsc.c \
		  platform/kirin/file_encry_v3/sec_fbe3_km.c
# face_recognize
CFILES += platform/kirin/face_recognize/tee_face_recognize.c


# video_decrypt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/
CFILES += platform/kirin/video_decrypt/vdec_mmap.c

# vdec-video_decoder
inc-flags += -I$(SOURCE_DIR)/platform/kirin/video_decrypt/

inc-flags += -DBALTIMORE_SFD_CONVERT
inc-flags += -I$(SOURCE_DIR)/platform/kirin/sensorhub
CFILES += platform/kirin/sensorhub/sensorhub_ipc.c

#vcodec
inc-flags += -DTEE_SUPPORT_HIVCODEC
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec/venc_hivna/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec
CFILES += platform/kirin/vcodec/hi_vcodec/sec_intf_para.c
CFILES += platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_tee.c
CFILES += platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_baltimore.c

#vdec_vfmw
include $(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec/sec_decoder.cfg

# p73
inc-flags += -DPLATFORM_NO_HISEE_FLAG
inc-flags += -DSE_VENDOR_NXP
inc-flags += -DHISI_TEE
inc-flags += -DSE_SUPPORT_MULTISE
inc-flags += -DSE_SUPPORT_SN110
inc-flags += -DSE_SUPPORT_ST
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61/lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/t1
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/pal
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/common
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/spm
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/utils
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/pal/spi

CFILES += platform/kirin/eSE/p61/p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEse_Api_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEse_Api_hisi_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEseDataMgr_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEseProto7816_3_p61.c
CFILES += platform/kirin/eSE/t1/t1.c
CFILES += platform/kirin/eSE/p73/p73.c
CFILES += platform/kirin/eSE/p73/pal/spi/phNxpEsePal_spi.c
CFILES += platform/kirin/eSE/p73/pal/phNxpEsePal.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Api.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Api_hisi.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Apdu_Api.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEseDataMgr.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEseProto7816_3.c
CFILES += platform/kirin/eSE/p73/utils/ese_config_hisi.c
CFILES += platform/kirin/eSE/p73/utils/ringbuffer.c

ifeq ($(FEATURE_HISI_MSP_ENGINE_LIBCRYPTO), true)
inc-flags += -DCONFIG_HISI_MSP_ENGINE_LIBCRYPTO \
	-DCONFIG_HISI_MSPE_SMMUV3
include $(SOURCE_DIR)/platform/kirin/msp_engine/Makefile
# HIAI mesp_decrypt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/mesp_decrypt
inc-flags += -I$(HI_PLAT_ROOT_DIR)/custom/include
CFILES += platform/kirin/mesp_decrypt/mesp_decrypt.c
endif

# privacy protection
ifeq ($(CONFIG_HISI_PRIVACY_PROTECTION), true)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/privacy_protection
inc-flags += -I$(SOURCE_DIR)/platform/kirin/msp_engine/include
inc-flags += -DCONFIG_HISI_PRIVACY_PROTECTION
CFILES += platform/kirin/privacy_protection/privacy_protection_common.c \
          platform/kirin/privacy_protection/privacy_protection_syscall.c
endif

#mspc(inse)
ifneq ($(product_range),base)
ifeq ($(CONFIG_HISI_MSPC), true)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61
inc-flags += -I$(SOURCE_DIR)/platform/kirin/mspc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/mspc/apdu
inc-flags += -I$(SOURCE_DIR)/platform/kirin/mspc/test
inc-flags += -DMSP_EXT_TPDU
inc-flags += -DPLATFORM_NO_HISEE_FLAG
inc-flags += -DCONFIG_HISI_MSPC
CFILES += \
		  platform/kirin/eSE/se_dummy.c \
		  platform/kirin/mspc/mspc.c \
		  platform/kirin/mspc/mspc_ipc.c \
		  platform/kirin/mspc/mspc_power.c \
		  platform/kirin/mspc/mspc_api.c \
          platform/kirin/mspc/apdu/mspc_tpdu.c

ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DMSPC_DRIVER_TEST
        CFILES += platform/kirin/mspc/test/mspc_test.c \
                  platform/kirin/mspc/test/mspc_test_performance.c
ifeq ($(CONFIG_HISI_MSPC_IPC_TEST), true)
inc-flags += -DCONFIG_HISI_MSPC_IPC_TEST
CFILES += platform/kirin/mspc/test/mspc_ipc_test.c
endif
endif
endif
endif

#seplat
ifeq ($(CONFIG_FEATURE_SEPLAT), true)

inc-flags += -I$(TOPDIR)/../../../../hisi/hise/include/common

include $(SOURCE_DIR)/platform/kirin/seplat/libseplat_external/libseplat_external.mk

#SEPLAT_DATA_LINK
inc-flags += -I$(TOPDIR)/../../../../hisi/hise/include/common/data_link
#SEPLAT_DATA_LINK

inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/data_link/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/gpio
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/log
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/spi
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/thread
inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/timer

inc-flags += -DCONFIG_FEATURE_SEPLAT
inc-flags += -DCONFIG_FEATURE_SEPLAT_GP
CFILES += \
	platform/kirin/seplat/interface_adaptation/spi/seplat_hal_spi.c \
	platform/kirin/seplat/interface_adaptation/thread/seplat_hal_thread.c \
	platform/kirin/seplat/interface_adaptation/timer/seplat_hal_timer.c \
	platform/kirin/seplat/interface_adaptation/gpio/seplat_hal_gpio.c \
	platform/kirin/seplat/interface_adaptation/data_link/seplat_data_link.c \
	platform/kirin/seplat/interface_adaptation/log/seplat_external_log.c \
	platform/kirin/seplat/interface_adaptation/log/seplat_hal_log.c

CFILES += \
	$(SOURCE_DIR)/platform/kirin/seplat/seplat.c \
	$(SOURCE_DIR)/platform/kirin/seplat/seplat_power.c \
	$(SOURCE_DIR)/platform/kirin/seplat/seplat_status.c \

ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DCONFIG_FEATURE_SEPLAT_TEST
inc-flags += -DCONFIG_SEPLAT_TEST
CFILES += $(SOURCE_DIR)/platform/kirin/seplat/seplat_test.c

inc-flags += -I$(SOURCE_DIR)/platform/kirin/seplat/interface_adaptation/data_link/test
CFILES += platform/kirin/seplat/interface_adaptation/data_link/test/seplat_dl_test_entry.c
endif
endif

#msp_ta_channel
inc-flags += -I$(SOURCE_DIR)/platform/kirin/msp_ta_channel
ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DMSP_TA_CHANNEL
CFILES += platform/kirin/msp_ta_channel/msp_ta_channel.c
endif

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

# teeos shared memmory
CFILES += platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem
