ifneq ($(filter baltimore,$(TARGET_BOARD_PLATFORM)),)
inc-flags += -DTEE_SUPPORT_SECISP
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/baltimore
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/hisp_mem.c
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/hisp_load.c
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/hisp_secboot.c
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/baltimore/hisp_pwr.c
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/baltimore/hisp.c
ifeq ($(chip_type),es)
inc-flags += -DISP_CHIP_ES
endif
endif

ifneq ($(filter kirin990,$(TARGET_BOARD_PLATFORM)),)
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
ifneq ($(product_type), armpc)
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
endif
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),denver laguna),)
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),burbank kirin970 kirin980 kirin710 orlando),)
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/revisions
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/revisions/hisp.c
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),miamicw),)
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv_key/isp/revisions
CFILES += platform/libthirdparty_drv/plat_drv_key/isp/revisions/hisp.c
endif

