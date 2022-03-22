# hi3670
# hisi common includes
inc-flags += -I$(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/kirin970 \
			 -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secureboot/bspatch \
			 -I$(TOPDIR)/libs/libplatdrv/platform/common/include/hifi \
			 -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secmem/include \
			 -I$(TOPDIR)/libs/libplatdrv/platform/common/include/ivp

#modem start
BALONG_TOPDIR := $(SOURCE_DIR)/../../../../../../../vendor/hisi

inc-flags += -I$(BALONG_TOPDIR)/modem/config/product/$(OBB_PRODUCT_NAME)/config
#modem end

# i2c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i2c
CFILES += platform/kirin/i2c/i2c.c

# spi
CFILES += platform/kirin/spi/spi.c

# gpio
CFILES += platform/kirin/gpio/gpio.c

# dma
CFILES += platform/kirin/dma/dma.c

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
			 -I$(SOURCE_DIR)/platform/common/include \
			 -I$(SOURCE_DIR)/platform/kirin/include/platform/kirin970 \
			 -I$(SOURCE_DIR)/platform/kirin/include

# modem
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

# hifi
inc-flags += -DCONFIG_SUPPORT_HIFI_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/hifi
CFILES += platform/kirin/hifi/hifi_reload.c

ifeq ($(WITH_MODEM), true)
CFILES += platform/kirin/secureboot/process_modem_info.c
else
CFILES += platform/kirin/modem/adp/bsp_modem_stub.c
CFILES += platform/kirin/secureboot/process_modem_info_stub.c
endif

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
inc-flags += -I$(SOURCE_DIR)/platform/common/display
CFILES += platform/common/display/hisi_disp.c \
	  platform/common/display/hisi_fb_sec.c \
	  platform/common/display/hisifd_overlay_utils.c

# Mate10 related sources "WITH_CHIP_HI3570"
CFILES += platform/common/display/hisi_overlay_utils_kirin970.c \
	  platform/common/display/hisi_hdcp.c
inc-flags += -DCONFIG_DSS_TYPE_KIRIN970

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
	  platform/common/touchscreen/panel/tui_ssl.c		\
	  platform/common/touchscreen/panel/tui_gtx8.c		\
	  platform/common/touchscreen/panel/tui_elan.c

inc-flags += -I$(SOURCE_DIR)/platform/common
CFILES += $(wildcard platform/common/tui_drv/*.c)

# fingerprint
CFILES += platform/kirin/fingerprint/src/tee_fingerprint.c

# face_recognize
CFILES += platform/kirin/face_recognize/tee_face_recognize.c

# inse
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

# p61
inc-flags += -DSE_VENDOR_NXP
inc-flags += -I$(SOURCE_DIR)/platform/common
CFILES += platform/kirin/eSE/p61/p61.c

ifeq ($(CONFIG_DX_ENABLE), true)
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
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc63
CFILES += platform/common/cc_driver/cc63/cc_driver_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
CFILES += platform/kirin/ccdriver_lib/cc_power.c

# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

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

# secmem_ddr
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_SEC_CFG

CFILES += platform/kirin/secmem/driver/sec/ddr_sec_init.c
CFILES += platform/kirin/secmem/driver/sec/kirin970_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/tzmp2.c
inc-flags += -DCONFIG_HISI_DDR_SEC_IDENTIFICATION

# isp
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/revisions
CFILES += platform/kirin/isp/revisions/hisp.c

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

# tzpc
inc-flags += -I$(SOURCE_DIR)/platform/common/tzpc
CFILES += platform/common/tzpc/tzpc_cfg.c

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk

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
