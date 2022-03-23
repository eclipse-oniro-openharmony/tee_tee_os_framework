
MODULE := libisp.a

include $(TOPDIR)/mk/var.mk

c-flags += -Wall -Wextra

ifneq ($(filter baltimore,$(TARGET_BOARD_PLATFORM)),)
c-flags += -DTEE_SUPPORT_SECISP
isp_c_files += hisp_mem.c
isp_c_files += hisp_secboot.c
isp_c_files += baltimore/hisp_pwr.c
isp_c_files += hisp_load.c
isp_c_files += baltimore/hisp.c
ifeq ($(chip_type),es)
inc-flags += -DISP_CHIP_ES
endif
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp/baltimore
inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/baltimore
endif

ifneq ($(filter kirin990,$(TARGET_BOARD_PLATFORM)),)
c-flags += -DCONFIG_SUPPORT_ISP_LOAD
ifneq ($(product_type), armpc)
c-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
isp_c_files += platform/libthirdparty_drv/plat_drv_key/isp/kirin990/hisp.c
endif
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
ifneq ($(chip_type),cs2)
inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/kirin990
else
inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/kirin990_cs2
endif
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),denver laguna),)
c-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
c-flags += -DCONFIG_SUPPORT_ISP_LOAD
c-flags += -DTEE_SUPPORT_SECISP
isp_c_files += platform/kirin/isp/kirin990/hisp.c
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp/kirin990
inc-flags += -I$(TOPDIR)/../../../../hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),burbank kirin970 kirin980 kirin710 orlando),)
c-flags += -DCONFIG_SUPPORT_ISP_LOAD
c-flags += -DCONFIG_HISI_ISP_SEC_IMAGE
isp_c_files += platform/kirin/isp/revisions/hisp.c
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp/revisions
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM),miamicw),)
c-flags += -DCONFIG_SUPPORT_ISP_LOAD
isp_c_files += platform/kirin/isp/revisions/hisp.c
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp/revisions
endif


inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/common/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/common/include/isp
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv_key/isp
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/plat_drv/secmem/include
inc-flags += -I$(TOPDIR)/drivers/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/include
inc-flags += -I$(TOPDIR)/drivers/platdrv/platform/libthirdparty_drv/include

include $(TOPDIR)/mk/lib-common.mk
