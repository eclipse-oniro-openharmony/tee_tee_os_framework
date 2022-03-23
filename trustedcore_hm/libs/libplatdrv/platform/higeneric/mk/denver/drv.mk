# denver
#NPU //denver enable compile
ifneq ($(product_type),lite)

AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/denver
NPU_DRIVER_INC_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/npu/inc/driver

inc-flags += -DTEE_SUPPORT_NPU
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/uapi
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/comm
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/device/common
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/device/resource
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/manager
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/platform/
#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/platform/hi6290
inc-flags += -I$(AP_PLAT_HEAD_PATH)
inc-flags += -I$(NPU_DRIVER_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

#npu kernel driver
#platform module
CFILES += platform/kirin/npu_v100/platform/hi6290/npu_adapter.c
CFILES += platform/kirin/npu_v100/platform/npu_irq.c
CFILES += platform/kirin/npu_v100/platform/npu_reg.c
CFILES += platform/kirin/npu_v100/platform/npu_dfx.c
CFILES += platform/kirin/npu_v100/platform/npu_gic.c
CFILES += platform/kirin/npu_v100/platform/npu_resmem.c
CFILES += platform/kirin/npu_v100/platform/npu_feature.c
CFILES += platform/kirin/npu_v100/platform/npu_platform.c

#device common module
CFILES += platform/kirin/npu_v100/device/common/npu_common.c
CFILES += platform/kirin/npu_v100/device/common/npu_cma.c
CFILES += platform/kirin/npu_v100/device/common/npu_shm.c
CFILES += platform/kirin/npu_v100/device/common/npu_mailbox_msg.c
CFILES += platform/kirin/npu_v100/device/common/npu_doorbell.c
CFILES += platform/kirin/npu_v100/device/common/npu_pm.c
CFILES += platform/kirin/npu_v100/device/common/npu_devinit.c

#device resource module
CFILES += platform/kirin/npu_v100/device/resource/npu_mailbox.c
CFILES += platform/kirin/npu_v100/device/resource/npu_mailbox_utils.c
CFILES += platform/kirin/npu_v100/device/resource/npu_calc_sq.c
CFILES += platform/kirin/npu_v100/device/resource/npu_calc_cq.c
CFILES += platform/kirin/npu_v100/device/resource/npu_stream.c
CFILES += platform/kirin/npu_v100/device/resource/npu_sink_stream.c
CFILES += platform/kirin/npu_v100/device/resource/npu_event.c
CFILES += platform/kirin/npu_v100/device/resource/npu_model.c
CFILES += platform/kirin/npu_v100/device/resource/npu_task.c
CFILES += platform/kirin/npu_v100/device/resource/npu_semaphore.c

#device service module
CFILES += platform/kirin/npu_v100/device/service/npu_calc_channel.c
#CFILES += platform/kirin/npu_v100/device/service/npu_reg.c

#manager module
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/device/service
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/inc
CFILES += platform/kirin/npu_v100/manager/npu_proc_ctx.c
CFILES += platform/kirin/npu_v100/manager/npu_ioctl_services.c
CFILES += platform/kirin/npu_v100/manager/npu_manager_ioctl_services.c
CFILES += platform/kirin/npu_v100/manager/npu_recycle.c
CFILES += platform/kirin/npu_v100/manager/npu_manager_common.c
CFILES += platform/kirin/npu_v100/manager/npu_manager.c
#CFILES += platform/kirin/npu_v100/manager/
endif

# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include \
	    -I$(SOURCE_DIR)/platform/kirin/include/platform/denver

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

# i3c
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
CFILES += platform/kirin/dma/dma.c

# tzpc
inc-flags += -I$(SOURCE_DIR)/platform/common/tzpc
CFILES += platform/common/tzpc/tzpc_cfg.c

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include


# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

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

ifeq ($(WITH_ENG_VERSION), true)
CFILES += platform/kirin/secmem/driver/sion/sion_test.c
endif

# secsvm
ifeq ($(WITH_ENG_VERSION),true)
inc-flags += -DTEE_SVM_DEBUG
endif

ifneq ($(product_type),lite)
inc-flags += -DTEE_SUPPORT_SVM
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/driver/
CFILES += platform/kirin/secsvm/driver/hisi_teesvm.c
CFILES += platform/kirin/secsvm/driver/hisi_teesvm_helper.c
endif

# secmem_ddr
COMPILE_SEC_DDR_TEST := false
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
#inc-flags += -DCONFIG_HISI_DDR_CA_RD
inc-flags += -DCONFIG_HISI_SEC_DDR_SUB_RGN
CFILES += platform/kirin/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/kirin/secmem/driver/sec/denver_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/denver/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/denver/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
CFILES += platform/kirin/secmem/driver/sec/denver/sec_region_test.c
inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif

# isp
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -DTEE_SUPPORT_SECISP
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/kirin990
CFILES += platform/kirin/isp/kirin990/hisp.c

# ivp
inc-flags += -I$(SOURCE_DIR)/platform/common/include/ivp
CFILES += platform/kirin/ivp/hivp.c

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO


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
	  platform/kirin/secureboot/process_hifi_info.c \
	  platform/kirin/secureboot/process_isp_info.c

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
		  platform/common/cc_driver/cc_driver_hal.c
# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
inc-flags += -I$(SOURCE_DIR)/platform/common/display2.0
CFILES += platform/common/display2.0/hisi_disp.c \
          platform/common/display2.0/hisi_fb_sec.c \
          platform/common/display2.0/hisi_overlay_utils.c \
          platform/common/display2.0/hisi_dss_module_registe.c

# Mate10 related sources "WITH_CHIP_HI3570"
CFILES += platform/common/display2.0/reg_dfc/hisi_dss_dfc_kirin980_base.c \
          platform/common/display2.0/reg_dma/hisi_dss_dma_kirin980_base.c \
          platform/common/display2.0/reg_ldi/hisi_dss_ldi_kirin990_base.c \
          platform/common/display2.0/reg_mctl/hisi_dss_mctl_kirin980_base.c \
          platform/common/display2.0/reg_mif/hisi_dss_mif_kirin980_base.c \
          platform/common/display2.0/reg_mix/hisi_dss_mix_kirin980_base.c \
          platform/common/display2.0/reg_ovl/hisi_dss_ovl_kirin980_base.c \
          platform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin980_base.c \
          platform/common/display2.0/channel_data/hisi_dss_channel_data_denver_base.c
inc-flags += -DCONFIG_DSS_TYPE_DENVER

# touchscheen
inc-flags += -I$(SOURCE_DIR)/platform/common/touchscreen		\
	    -I$(SOURCE_DIR)/platform/common/touchscreen/panel	\
	    -I$(SOURCE_DIR)/platform/kirin/touchscreen
CFILES += \
	platform/common/touchscreen/hisi_tui_touchscreen.c \
	platform/common/touchscreen/panel/tui_amtel.c \
	platform/common/touchscreen/panel/tui_jdi.c \
	platform/common/touchscreen/panel/tui_novatek.c \
	platform/common/touchscreen/panel/tui_himax.c \
	platform/common/touchscreen/panel/tui_parade.c \
	platform/common/touchscreen/panel/tui_st.c \
	platform/common/touchscreen/panel/tui_st_new.c \
	platform/common/touchscreen/panel/tui_sec.c \
	platform/common/touchscreen/panel/tui_synaptics.c \
	platform/common/touchscreen/panel/tui_synaptics_tcm.c \
	platform/common/touchscreen/panel/tui_fts.c \
	platform/common/touchscreen/panel/tui_gt1x.c \
	platform/common/touchscreen/panel/tui_gtx8.c \
	platform/common/touchscreen/panel/tui_ssl.c \
	platform/common/touchscreen/panel/tui_elan.c

inc-flags += -I$(SOURCE_DIR)/platform/common
CFILES += $(wildcard platform/common/tui_drv/*.c)

# fingerprint
CFILES += platform/kirin/fingerprint/src/tee_fingerprint.c

# I2C ESE open in denver
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -DCONFIG_ESE_TEE2ATF_LOCK
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/hisee
CFILES += \
		  platform/kirin/eSE/se_dummy.c \
		  platform/kirin/eSE/hisee/ese_data_handle.c


# Encrypted Image Incremental Update Service(eiius)
inc-flags += -DCONFIG_HISI_EIIUS
CFILES += platform/kirin/secureboot/eiius_interface.c

# file encry
inc-flags += -I$(SOURCE_DIR)/platform/kirin/file_encry
CFILES += \
		  platform/kirin/file_encry/sec_ufs_km.c \
		  platform/kirin/file_encry/sec_derive_key.c \
		  platform/kirin/file_encry/sec_ufs_key_drv.c
# face_recognize
CFILES += platform/kirin/face_recognize/tee_face_recognize.c

# video_decrypt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/
CFILES += platform/kirin/video_decrypt/vdec_mmap.c

# vdec-video_decoder
inc-flags += -I$(SOURCE_DIR)/platform/kirin/video_decrypt/

#vcodec
inc-flags += -DTEE_SUPPORT_HIVCODEC
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec/venc_hivna/
CFILES += platform/kirin/vcodec/hi_vcodec/sec_intf.c
CFILES += platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_tee.c
CFILES += platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_stub.c

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

# hieps
ifeq ($(FEATURE_HISI_HIEPS), true)
    export SEC_DFT_ENABLE := $(WITH_ENG_VERSION)
    export SEC_PRODUCT = $(TARGET_BOARD_PLATFORM)
    export PROJECT_ROOT_DIR = $(SOURCE_DIR)
    include $(SOURCE_DIR)/platform/kirin/hieps/Makefile
    SEC_CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(SEC_CFILES))
    $(info HIEPS SEC_INCS = $(SEC_INCS) -I$(SOURCE_DIR)/platform/kirin/hieps/include)
    $(info HIEPS SEC_CFLAGS = $(SEC_CFLAGS))
    $(info HIEPS SEC_CFILES = $(SEC_CFILES))
    CFILES += $(SEC_CFILES)
    CFILES := $(addprefix $(TOPDIR)/libs/libplatdrv/,$(CFILES))
    inc-flags += $(SEC_INCS) \
                -I$(SOURCE_DIR)/platform/kirin/hieps/include
    c-flags += $(SEC_CFLAGS)
endif

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

