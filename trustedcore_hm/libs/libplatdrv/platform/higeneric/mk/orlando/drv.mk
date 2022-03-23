# orlando

#modem start
BALONG_TOPDIR := $(SOURCE_DIR)/../../../../../../../vendor/hisi

inc-flags += -I$(BALONG_TOPDIR)/modem/config/product/$(OBB_PRODUCT_NAME)/config
#modem end

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib must be first
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
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
CFILES += platform/kirin/ccdriver_lib/cc_adapt.c
CFILES += platform/kirin/ccdriver_lib/cc_power.c
# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

#NPU //hi6280 enable compile
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/orlando
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
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/platform/hi6280
inc-flags += -I$(AP_PLAT_HEAD_PATH)
inc-flags += -I$(NPU_DRIVER_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

#npu kernel driver
#platform module
CFILES += platform/kirin/npu_v100/platform/hi6280/npu_adapter.c
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


# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include \
	    -I$(SOURCE_DIR)/platform/kirin/include/platform/orlando

# i2c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i2c
CFILES += platform/kirin/i2c/i2c.c

# spi
CFILES += platform/kirin/spi/spi.c

# gpio
CFILES += platform/kirin/gpio/gpio.c

# dma
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
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/include
CFILES += platform/kirin/secmem/driver/sion/sion.c \
	  platform/kirin/secmem/driver/iommu/siommu.c \
	  platform/kirin/secmem/driver/lib/genalloc.c \
	  platform/kirin/secmem/driver/lib/bitmap.c
ifeq ($(WITH_ENG_VERSION), true)
CFILES += platform/kirin/secmem/driver/sion/sion_test.c
endif

# secsvm
ifeq ($(WITH_ENG_VERSION),true)
inc-flags += -DTEE_SVM_DEBUG
endif

inc-flags += -DTEE_SUPPORT_SVM
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/driver/
CFILES += platform/kirin/secsvm/driver/hisi_teesvm.c
CFILES += platform/kirin/secsvm/driver/hisi_teesvm_helper.c

# secmem_ddr
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET

CFILES += platform/kirin/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/kirin/secmem/driver/sec/orlando_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/orlando/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/orlando/tzmp2.c
inc-flags += -DCONFIG_HISI_DDR_SEC_IDENTIFICATION
inc-flags += -DCONFIG_HISI_DDR_SEC_TUI
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

# isp
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/revisions
CFILES += platform/kirin/isp/revisions/hisp.c

# ivp
inc-flags += -I$(SOURCE_DIR)/platform/common/include/ivp
CFILES += platform/kirin/ivp/hivp.c

# modem
#aslr
inc-flags += -DCONFIG_MODEM_BALONG_ASLR

inc-flags += -I$(SOURCE_DIR)/platform/kirin/modem/icc \
	    -I$(SOURCE_DIR)/platform/kirin/modem/include
ifeq ($(WITH_MODEM), true)
CFILES += platform/kirin/modem/adp/adp_icc.c \
	  platform/kirin/modem/adp/bsp_modem_call.c \
	  platform/kirin/modem/adp/bsp_param_cfg.c \
	  platform/kirin/modem/adp/bsp_secboot_adp.c

ICC_CFILES = platform/kirin/modem/icc/ipc_core.c \
	  platform/kirin/modem/icc/icc_core.c \
	  platform/kirin/modem/icc/icc_debug.c \
	  platform/kirin/modem/icc/icc_secos.c

CFILES += $(ICC_CFILES)
endif

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME

inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

CFILES += platform/kirin/secureboot/secureboot.c \
	  platform/kirin/secureboot/secboot.c \
	  platform/kirin/secureboot/process_hifi_info.c \
	  platform/kirin/secureboot/process_isp_info.c \
	  platform/kirin/secureboot/zlib/adler32.c \
	  platform/kirin/secureboot/zlib/inffast.c \
	  platform/kirin/secureboot/zlib/inflate.c \
	  platform/kirin/secureboot/zlib/inftrees.c \
	  platform/kirin/secureboot/zlib/uncompr.c \
	  platform/kirin/secureboot/zlib/zutil.c

inc-flags += -DBALONG_MODEM_CERT
ifeq ($(WITH_MODEM), true)
CFILES += platform/kirin/modem/adp/sec_modem_dump.c
CFILES += platform/kirin/secureboot/process_modem_info.c
else
CFILES += platform/kirin/modem/adp/bsp_modem_stub.c
CFILES += platform/kirin/secureboot/process_modem_info_stub.c
endif

CFILES  +=  \
          platform/kirin/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE

#modem_cold_patch
inc-flags += -DCONFIG_COLD_PATCH
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

# modem trng
ifeq ($(WITH_MODEM), true)
inc-flags += -DCONFIG_MODEM_TRNG
CFILES += platform/kirin/modem/trng/trng_seed.c
endif

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
inc-flags += -I$(SOURCE_DIR)/platform/common/display
CFILES += platform/common/display/hisi_disp.c			\
	  platform/common/display/hisi_fb_sec.c			\
	  platform/common/display/hisifd_overlay_utils.c

# Mate10 related sources "WITH_CHIP_HI3570"
CFILES += platform/common/display/hisi_overlay_utils_orlando.c
inc-flags += -DCONFIG_DSS_TYPE_ORLANDO

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

# I2C ESE open in orlando
inc-flags += -DSE_USE_ESE_I2C
inc-flags += -DSE_VENDOR_HISEE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/hisee
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61
CFILES += \
		  platform/kirin/eSE/se_dummy.c \
		  platform/kirin/eSE/hisee/hisee.c \
		  platform/kirin/eSE/hisee/ese_data_handle.c \
		  platform/kirin/eSE/hisee/ipc_a.c \
		  platform/kirin/eSE/hisee/ipc_msg.c

#Encrypted Image Incremental Update Service(eiius)
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

#NPU //hi3680 enable compile
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu
CFILES += platform/kirin/npu/npu_main_sec.c  \
		  platform/kirin/npu/npu_smmu_sec.c   \
		  platform/kirin/npu/npu_task_sec.c    \
		  platform/kirin/npu/npu_task_sswq_sec.c  \
		  platform/kirin/npu/npu_task_wq_sec.c

inc-flags += -DCONFIG_HISI_NVIM_SEC

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

# sensorhub
# p61
inc-flags += -DSE_VENDOR_NXP
CFILES += platform/kirin/eSE/p61/p61.c
CFILES := $(addprefix $(TOPDIR)/libs/libplatdrv/,$(CFILES))

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem
