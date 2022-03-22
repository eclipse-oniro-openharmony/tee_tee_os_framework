# display, from trustedcore/platform/common/display/Android.mk
# TUI_FEATURE must be true
list(APPEND PLATDRV_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/display2.0
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/libthirdparty_drv/plat_drv/display2.0/hdcp
)
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/display2.0/hisi_disp.c
    platform/libthirdparty_drv/plat_drv/display2.0/hisi_fb_sec.c
    platform/libthirdparty_drv/plat_drv/display2.0/hisi_overlay_utils.c
    platform/libthirdparty_drv/plat_drv/display2.0/hisi_dss_module_registe.c
    platform/libthirdparty_drv/plat_drv/display2.0/hdcp_syscall.c
)

# Mate10 related sources "WITH_CHIP_HI3570"
list(APPEND TEE_C_SOURCES
    platform/libthirdparty_drv/plat_drv/display2.0/reg_dfc/hisi_dss_dfc_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_dma/hisi_dss_dma_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_ldi/hisi_dss_ldi_kirin990_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_mctl/hisi_dss_mctl_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_mif/hisi_dss_mif_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_mix/hisi_dss_mix_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_ovl/hisi_dss_ovl_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/reg_smmu/hisi_dss_smmu_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/channel_data/hisi_dss_channel_data_kirin980_base.c
    platform/libthirdparty_drv/plat_drv/display2.0/hdcp/hisi_hdcp_common.c
    platform/libthirdparty_drv/plat_drv/display2.0/hdcp/hisi_hdcp_esm.c
)
list(APPEND TEE_C_DEFINITIONS
    CONFIG_DSS_TYPE_KIRIN990
)