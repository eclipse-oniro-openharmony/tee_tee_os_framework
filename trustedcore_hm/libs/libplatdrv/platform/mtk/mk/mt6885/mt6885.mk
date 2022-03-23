# ccdriver_lib
inc-flags += -I$(SOURCE_DIR)/platform/mtk/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/crys/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/driver/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/host/src/cc710teelib/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rsa/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/utils/src/common/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rnd_dma/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/pki/pka/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/common/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/api/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/fips/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/proj/cc710tee/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/ecc/ecc_domains/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/hmos/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/mtk
CFILES += platform/common/cc_driver/mtk/cc_driver_adapt.c
CFILES += platform/mtk/ccdriver_lib/mtk_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
CFILES += platform/mtk/ccdriver_lib/cc_driver_syscall.c

# secboot
CFILES += platform/mtk/secboot/secureboot.c

# for oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c

# spi
inc-flags += -I$(SOURCE_DIR)/platform/mtk/spi/inc
CFILES += platform/mtk/spi/spi_mtk.c

# fignerprint
CFILES += platform/mtk/fingerprint/src/tee_fingerprint.c

# tp
inc-flags += -I$(SOURCE_DIR)/platform/common/touchscreen
inc-flags += -I$(SOURCE_DIR)/platform/common/tui_drv
inc-flags += -I$(SOURCE_DIR)/platform/mtk/touchscreen
CFILES += platform/mtk/touchscreen/tui_touchscreen_panel.c
CFILES += platform/mtk/touchscreen/tui_touchscreen_platform.c
CFILES += platform/mtk/touchscreen/panel/tui_synaptics.c
CFILES += platform/mtk/touchscreen/panel/tui_gtx8.c

# gpio
inc-flags += -I$(SOURCE_DIR)/platform/mtk/gpio/inc
CFILES += platform/mtk/gpio/gpio_mtk.c
inc-flags += -I$(TOPDIR)/platform/mtk/phone/common/tee_config
ifeq ($(CONFIG_M_DRIVER), true)
inc-flags += -I$(SOURCE_DIR)/platform/mtk/drv_pal/include
CFILES += platform/mtk/drv_pal/src/drv_fwk.c
CFILES += platform/mtk/drv_pal/src/secmem_core_api.c

inc-flags += -I$(SOURCE_DIR)/platform/mtk/dynion/include
CFILES += platform/mtk/dynion/src/dynion.c
CFILES += platform/mtk/dynion/src/dynion_config.c
endif

# eima2.0+rootscan
CFILES += platform/mtk/antiroot/nonsecure_hasher.c
CFILES += platform/mtk/antiroot/sre_rwroot.c

# file based encryption
inc-flags += -I$(SOURCE_DIR)/platform/mtk/file_encry_v2/
CFILES += platform/mtk/file_encry_v2/sec_fbe2_km.c \
          platform/mtk/file_encry_v2/sec_fbe2_ufsc.c

# eSE
inc-flags += -DMTK_ESE
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/t1
CFILES += platform/mtk/eSE/se_dummy.c
ifneq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT)$(CONFIG_SE_SERVICE_64BIT)),)
CFILES += platform/mtk/eSE/se_syscall.c
endif

# t1
inc-flags += -DSE_SUPPORT_ST
inc-flags += -DSE_VENDOR_NXP
CFILES += platform/mtk/eSE/atf/atf.c
CFILES += platform/mtk/eSE/t1/t1.c

#p73
inc-flags += -DSE_SUPPORT_MULTISE
inc-flags += -DSE_SUPPORT_SN110
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/spi_common
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/inc
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/pal
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/common
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/lib
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/spm
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/utils
inc-flags += -I$(SOURCE_DIR)/platform/mtk/eSE/p73/pal/spi
CFILES += platform/mtk/eSE/spi_common/spi_common.c
CFILES += platform/mtk/eSE/p73/p73.c
CFILES += platform/mtk/eSE/p73/pal/spi/phNxpEsePal_spi.c
CFILES += platform/mtk/eSE/p73/pal/phNxpEsePal.c
CFILES += platform/mtk/eSE/p73/lib/phNxpEse_Api.c
CFILES += platform/mtk/eSE/p73/lib/phNxpEse_Api_hisi.c
CFILES += platform/mtk/eSE/p73/lib/phNxpEse_Apdu_Api.c
CFILES += platform/mtk/eSE/p73/lib/phNxpEseDataMgr.c
CFILES += platform/mtk/eSE/p73/lib/phNxpEseProto7816_3.c
CFILES += platform/mtk/eSE/p73/utils/ese_config_hisi.c
CFILES += platform/mtk/eSE/p73/utils/ringbuffer.c

inc-flags += -I$(SOURCE_DIR)/platform/common
CFILES += $(wildcard platform/common/tui_drv/*.c)
CFILES += $(wildcard platform/common/touchscreen/tui_touchscreen.c)

# TUI_FEATURE must be true
DISP_COMMON_INC_PATH:= $(SOURCE_DIR)/platform/mtk/tui
DISP_MT6885_INC_PATH:= $(DISP_COMMON_INC_PATH)/mt6885
DISP_INC_PATH:= $(DISP_MT6885_INC_PATH)/platforms/display/mt6885
CMDQ_INC_PATH:= $(DISP_MT6885_INC_PATH)/platforms/cmdq
M4U_INC_PATH:= $(DISP_MT6885_INC_PATH)/platforms/m4u
GENERIC_PATH:= $(DISP_MT6885_INC_PATH)/platforms/generic

inc-flags += -I$(DISP_MT6885_INC_PATH)
inc-flags += -I$(DISP_MT6885_INC_PATH)/platforms/generic
inc-flags += -I$(DISP_MT6885_INC_PATH)/inc
inc-flags += -I$(DISP_INC_PATH)/include
inc-flags += -I$(CMDQ_INC_PATH)
inc-flags += -I$(M4U_INC_PATH)

# HUAWEI iTrustee Adapter
CFILES += ${DISP_COMMON_INC_PATH}/dr_api.c

# LOG
CFILES += ${DISP_MT6885_INC_PATH}/platforms/generic/mtk_log.c

# Display Drivers
CFILES += ${DISP_INC_PATH}/display_tui.c \
		  ${DISP_INC_PATH}/ddp_drv.c \
		  ${DISP_INC_PATH}/ddp_info.c \
		  ${DISP_INC_PATH}/ddp_debug.c \
		  ${DISP_INC_PATH}/ddp_path.c \
		  ${DISP_INC_PATH}/ddp_rdma.c \
		  ${DISP_INC_PATH}/ddp_dsi.c \
		  ${DISP_INC_PATH}/ddp_dump.c \
		  ${DISP_INC_PATH}/ddp_color_format.c \
		  ${DISP_INC_PATH}/ddp_ovl.c \
		  ${DISP_INC_PATH}/display_tui_hal.c

# CMDQ SEC
CFILES += ${CMDQ_INC_PATH}/cmdq_sec_record.c \
		  ${CMDQ_INC_PATH}/cmdq_sec_core.c \
		  ${CMDQ_INC_PATH}/cmdq_sec_platform.c

# M4U SEC
CFILES += ${M4U_INC_PATH}/tui_m4u.c

#gatekeeper syscall
include $(SOURCE_DIR)/platform/common/gatekeeper/gatekeeper_drv.mk
