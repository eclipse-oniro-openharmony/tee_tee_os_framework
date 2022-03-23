# burbank
inc-flags += -I$(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/burbank

#NPU
#npu kernel driver
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
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/platform/hi6286

#platform module
CFILES += platform/kirin/npu_v100/platform/hi6286/npu_adapter.c
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

#manager module
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/device/service
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/inc
CFILES += platform/kirin/npu_v100/manager/npu_proc_ctx.c
CFILES += platform/kirin/npu_v100/manager/npu_ioctl_services.c
CFILES += platform/kirin/npu_v100/manager/npu_manager_ioctl_services.c
CFILES += platform/kirin/npu_v100/manager/npu_recycle.c
CFILES += platform/kirin/npu_v100/manager/npu_manager_common.c
CFILES += platform/kirin/npu_v100/manager/npu_manager.c
# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include

# isp
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/revisions
CFILES += platform/kirin/isp/revisions/hisp.c

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey/derive_teekey.mk

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT
inc-flags += -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO


inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
             -I$(SOURCE_DIR)/platform/kirin/secureboot/include \
             -I$(SOURCE_DIR)/platform/common/include/ivp \
             -I$(SOURCE_DIR)/platform/kirin/include

# use for baltimore and later platform
inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2

ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

CFILES += platform/kirin/secureboot/secureboot_v2.c \
          platform/kirin/secureboot/secboot.c \
          platform/kirin/secureboot/process_hifi_info.c \
          platform/kirin/secureboot/process_isp_info.c

CFILES  += platform/kirin/secureboot/process_ivp_info.c

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
          platform/common/cc_driver/cc_driver_hal.c \
          platform/kirin/ccdriver_lib/cc_adapt.c \
          platform/kirin/ccdriver_lib/cc_power.c \
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
inc-flags += -DCONFIG_DSS_TYPE_BURBANK

# file encry
inc-flags += -DCONFIG_FBE_UFS_KEY_WORKAROUND
inc-flags += -I$(SOURCE_DIR)/platform/kirin/file_encry_v3
CFILES += platform/kirin/file_encry_v3/sec_fbe3_ufsc.c \
          platform/kirin/file_encry_v3/sec_fbe3_km.c

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

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
inc-flags += -DTEE_SUPPORT_SVM
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/driver/
CFILES += platform/kirin/secsvm/driver/hisi_teesvm.c
CFILES += platform/kirin/secsvm/driver/hisi_teesvm_helper.c

# secmem_ddr
COMPILE_SEC_DDR_TEST := false
inc-flags += -DDDR_TWO_CHANNEL
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_CA_RD
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/include
CFILES += platform/kirin/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/kirin/secmem/driver/sec/burbank_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/burbank/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/burbank/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
CFILES += platform/kirin/secmem/driver/sec/burbank/sec_region_test.c
inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif

#msp_ta_channel
inc-flags += -I$(SOURCE_DIR)/platform/kirin/msp_ta_channel
ifeq ($(TARGET_BUILD_VARIANT),eng)
inc-flags += -DMSP_TA_CHANNEL
CFILES += platform/kirin/msp_ta_channel/msp_ta_channel.c
endif

ifeq ($(FEATURE_HISI_MSP_ENGINE_LIBCRYPTO), true)
inc-flags += -DCONFIG_HISI_MSP_ENGINE_LIBCRYPTO \
             -DCONFIG_HISI_MSPE_SMMUV2 \
             -DCONFIG_HISI_MSPE_POWER_SCHEME
include $(SOURCE_DIR)/platform/kirin/msp_engine/Makefile
endif

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
