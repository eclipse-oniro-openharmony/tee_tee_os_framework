# hi6250
# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include

# i2c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i2c
CFILES += platform/kirin/i2c/i2c.c

# spi
CFILES += platform/kirin/spi/spi.c

# gpio
CFILES += platform/kirin/gpio/gpio.c

# dma

# tzpc
inc-flags += -I$(SOURCE_DIR)/platform/common/tzpc
CFILES += platform/common/tzpc/tzpc_cfg.c

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

# seccfg
CFILES += platform/kirin/seccfg/sre_tzc.c

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c
# secmem
# TEE_SUPPORT_TZMP2 must be true

# secmem_ddr
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET

# isp
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/revisions
CFILES += platform/kirin/isp/revisions/hisp.c

# ivp
inc-flags += -I$(SOURCE_DIR)/platform/common/include/ivp

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

ifeq ($(WITH_MODEM), true)
CFILES += platform/kirin/secureboot/process_modem_info.c
else
CFILES += platform/kirin/modem/adp/bsp_modem_stub.c
CFILES += platform/kirin/secureboot/process_modem_info_stub.c
endif

#modem_cold_patch

# hifi
inc-flags += -DCONFIG_SUPPORT_HIFI_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/hifi
CFILES += platform/kirin/hifi/hifi_reload.c

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/ccdriver_lib/include
CFILES += platform/kirin/ccdriver_lib/cc_driver_init.c
CFILES += platform/kirin/ccdriver_lib/cc_driver_hal.c

# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true

# Mate10 related sources "WITH_CHIP_HI3570"

# touchscheen

# fingerprint
CFILES += platform/kirin/fingerprint/src/tee_fingerprint.c

# inse
# inse crypto
# file encry

# face_recognize
CFILES += platform/kirin/face_recognize/tee_face_recognize.c


# video_decrypt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/
CFILES += platform/kirin/video_decrypt/vdec_mmap.c

# vdec-video_decoder
inc-flags += -I$(SOURCE_DIR)/platform/kirin/video_decrypt/

#vcodec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/

c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/kirin/video_decoder/include
c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/kirin/video_decoder/driver

# sensorhub
# p61
inc-flags += -DSE_VENDOR_NXP
CFILES += platform/kirin/eSE/p61/p61.c
