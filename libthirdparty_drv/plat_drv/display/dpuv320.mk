# TUI_FEATURE must be true
inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/display
CFILES += platform/libthirdparty_drv/plat_drv/display/hisi_disp.c           \
          platform/libthirdparty_drv/plat_drv/display/hisi_fb_sec.c         \
          platform/libthirdparty_drv/plat_drv/display/hisifd_overlay_utils.c

CFILES += platform/libthirdparty_drv/plat_drv/display/hisi_overlay_utils_kirin710.c
inc-flags += -DCONFIG_DSS_TYPE_KIRIN710

