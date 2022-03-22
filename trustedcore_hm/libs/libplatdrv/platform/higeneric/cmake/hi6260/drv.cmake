list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/kirin710
    ${PROJECT_SOURCE_DIR}/../../../../vendor/hisi/modem/config/product/${OBB_PRODUCT_NAME}/config
)

set(USE_GNU_CXX y)
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
)

list(APPEND PLATDRV_LIBRARIES
    bz_hm
)

#oemkey
include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/spi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/gpio
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tzarch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/isp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/revisions
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/icc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include/bsdiff
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/hifi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p61
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/video_decrypt
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem
)

list(APPEND TEE_CPP_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/bspatch.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/buffer_file.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/extents.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/extents_file.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/file.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/memory_file.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/sink_file.cpp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/secure_bspatch.cpp
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c/i2c.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/spi/spi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/gpio/gpio.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/dma/dma.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc/tzpc_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/seccfg/hisi_hwspinlock.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/iommu/siommu.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/genalloc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/bitmap.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/kirin710_ddr_autofsgt_proxy_secure_os.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/sec_region.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/tzmp2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/revisions/hisp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secureboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_hifi_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_isp_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/adler32.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/inffast.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/inflate.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/inftrees.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/uncompr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/zlib/zutil.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hifi/hifi_reload.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display/hisi_disp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display/hisi_fb_sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display/hisifd_overlay_utils.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display/hisi_overlay_utils_kirin710.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/hisi_tui_touchscreen.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_amtel.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_jdi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_novatek.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_himax.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_parade.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_st.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_st_new.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_synaptics.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_synaptics_tcm.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_fts.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_gt1x.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_gtx8.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_ssl.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel/tui_elan.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/drv_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/mem_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/tui_drv.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/tui_timer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/fingerprint/src/tee_fingerprint.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/se_dummy.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee/hisee.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee/ese_data_handle.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee/ipc_a.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee/ipc_msg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p61/p61.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/face_recognize/tee_face_recognize.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/video_decrypt/vdec_mmap.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/sec_intf.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_tee.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_stub.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem/bl2_sharedmem.c
)
if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion_test.c
    )
endif()

if ("${WITH_MODEM}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/adp/adp_icc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/adp/bsp_modem_call.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/adp/bsp_param_cfg.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/adp/bsp_secboot_adp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/icc/ipc_core.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/icc/icc_core.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/icc/icc_debug.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/icc/icc_secos.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/trng/trng_seed.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_modem_info.c
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_MODEM_TRNG
    )
else()
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/modem/adp/bsp_modem_stub.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_modem_info_stub.c
    )
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc63
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc63/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_power.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/antiroot/nonsecure_hasher.c
    )
endif()

list(APPEND TEE_C_DEFINITIONS
    CONFIG_HISI_DDR_AUTO_FSGT
    CONFIG_HISI_DDR_SEC_CFC
    CONFIG_HISI_DDR_SEC_HIFI_RESET
    CONFIG_HISI_DDR_SEC_CFG
    CONFIG_SUPPORT_ISP_LOAD
    WITH_IMAGE_LOAD_SUPPORT
    CONFIG_DYNAMIC_MMAP_ADDR
    CONFIG_CHECK_PTN_NAME
    CONFIG_COLD_PATCH
    CONFIG_SUPPORT_HIFI_LOAD
    CONFIG_DSS_TYPE_KIRIN710
    SE_VENDOR_HISEE
    SE_VENDOR_NXP
    TEE_SUPPORT_HIVCODEC
)

if (NOT "${ap_cust_spec}" STREQUAL "2g_mem")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_AP_CUST_2G_MEM
    )
endif()
