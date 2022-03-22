# charlotte
inc-flags += -DTEMP_API_WITHOUT_ISP
# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include \
             -I$(TOPDIR)/libs/libplatdrv/platform/kirin/ccdriver_lib \
             -I$(SOURCE_DIR)/platform/kirin/include/platform/charlotte_es
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secureboot/bspatch \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/isp \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/hifi \
             -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secmem/include \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/ivp
CFILES += $(TOPDIR)/drivers/platdrv/src/temp_apis.c

# deleted when eps fit
CFILES += $(TOPDIR)/libs/libplatdrv/platform/common/soft_rand.c

#NPU //charlotte enable compile

#npu kernel driver
#platform module

#device resource module

#manager module


#socp

# c++

# i2c

# I3C

# spi

#fp_csi

#ipc_mailbox


# gpio

# dma

# tzpc

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey/derive_teekey_stub.mk

# tzarch

# seccfg

# hisi_hwspinlock

# secmem
# TEE_SUPPORT_TZMP2 must be true

# secmmuv3

# secmem_ddr

# isp

# ivp

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
             -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
             -I$(TOPDIR)/libs/libplatdrv/platform/kirin/ccdriver_lib/include \
             -I$(SOURCE_DIR)/platform/kirin/secureboot/include

inc-flags += -I$(SOURCE_DIR)/platform/kirin/include \
             -I$(SOURCE_DIR)/platform/common/include/ivp

inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2

ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

CFILES += platform/kirin/secureboot/secureboot_v2.c \
          platform/kirin/secureboot/secboot.c \
          platform/kirin/secureboot/cc_stub.c \
          platform/kirin/secureboot/process_hifi_info.c

CFILES  +=  \
          platform/kirin/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE

#hifi

# hdcp for wifidisplay(wfd)

# libfdt

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true


# touchscheen

# fingerprint

#ese

# file encry

# face_recognize


# video_decrypt

# vdec-video_decoder

#vcodec

# p73

# privacy protection

#mspc(inse)

# teeos shared memmory
CFILES += platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

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
