set(USE_GNU_CXX y)
set(COMPILE_SEC_DDR_TEST false)
list(APPEND PLATDRV_LIBRARIES
    bz_hm
)
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
)

if ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore_es
    )
endif()

# oemkey
include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/uapi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/manager
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/platform/hi36a0
    ${PROJECT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i3c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/mailbox
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tzarch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secsvm/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/isp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/baltimore
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include/bsdiff
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/hifi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hdcp_wfd
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hdcp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/panel
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry_v3
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/video_decrypt
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/sensorhub
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p61
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/t1
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/spm
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/utils
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/pal/spi
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/sdk/gpapi
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem
)
if ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/platform/hi36a0/npu_chip_cfg.c
    )
endif()
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/platform/hi36a0/npu_adapter.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_dev_ctx_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_event_info_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_hwts_driver.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_hwts_sqe.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_hwts_sq_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_model_info_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_pm.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_proc_ctx_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_schedule_task.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_semaphore.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_stream_info_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/device/npu_task_info_mngr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/manager/npu_custom_ioctl_services.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/manager/npu_ioctl_services.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/npu_v200/manager/npu_manager.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c/i2c.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i3c/i3c.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/spi/spi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mailbox/ipc_mailbox.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/gpio/gpio.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/dma/dma.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc/tzpc_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/seccfg/hisi_hwspinlock.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/iommu/siommu.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/genalloc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/bitmap.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion_recycling.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/iommu/sec_smmuv3.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/baltimore_ddr_autofsgt_proxy_secure_os.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/baltimore/sec_region.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/baltimore/tzmp2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/hisp_mem.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/hisp_load.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/hisp_secboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/baltimore/hisp_pwr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/baltimore/hisp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ivp/hivp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ivp/hivp_secboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secureboot_v2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_hifi_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_isp_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_ivp_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hifi/hifi_reload.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hdcp_wfd/hdcp_wfd.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/acpi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_addresses.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_empty_tree.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_overlay.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_ro.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_rw.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_strerror.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_sw.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_wip.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/libfdt/fdt_handler.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_disp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_fb_sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_overlay_utils.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_dss_module_registe.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hdcp_syscall.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_dfc/hisi_dss_dfc_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_dma/hisi_dss_dma_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_ldi/hisi_dss_ldi_kirin990_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_mctl/hisi_dss_mctl_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_mif/hisi_dss_mif_kirin9a0_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_mix/hisi_dss_mix_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_ovl/hisi_dss_ovl_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin9a0.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/channel_data/hisi_dss_channel_data_kirin9a0_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hdcp/hisi_hdcp_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hdcp/hisi_hdcp_soft.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hdcp/hisi_hdcp_dp.c
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
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee/ese_data_handle.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/eiius_interface.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry_v3/sec_fbe3_ufsc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry_v3/sec_fbe3_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/face_recognize/tee_face_recognize.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/video_decrypt/vdec_mmap.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/sensorhub/sensorhub_ipc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/sec_intf_para.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_tee.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/venc_baltimore.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p61/p61.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/t1/t1.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/p73.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/pal/spi/phNxpEsePal_spi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/pal/phNxpEsePal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib/phNxpEse_Api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib/phNxpEse_Api_hisi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib/phNxpEse_Apdu_Api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib/phNxpEseDataMgr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/lib/phNxpEseProto7816_3.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/utils/ese_config_hisi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p73/utils/ringbuffer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem/bl2_sharedmem.c
)

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion_test.c
    )
    list(APPEND TEE_C_DEFINITIONS
        TEE_SMMUV3_DEBUG
        CONFIG_HISI_SECBOOT_DEBUG
    )
endif()

if ("${COMPILE_SEC_DDR_TEST}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/kirin990/sec_region_test.c
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_SEC_DDR_TEST
    )
endif()

if ("${chip_type}" STREQUAL "es")
    list(APPEND TEE_C_DEFINITIONS
        ISP_CHIP_ES
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
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_power.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/eps_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/antiroot/nonsecure_hasher.c
    )
endif()

if ("${FEATURE_HISI_MSP_ENGINE_LIBCRYPTO}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_MSP_ENGINE_LIBCRYPTO
    )
    include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/msp_engine/msp_engine.cmake)
    list(APPEND TEE_C_SOURCES ${MSPE_C_SOURCES})
    list(APPEND TEE_C_DEFINITIONS ${MSPE_C_DEFINITIONS})
    list(APPEND TEE_INCLUDE_PATH ${MSPE_INCLUDE_PATH})
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mesp_decrypt
        ${HI_PLAT_ROOT_DIR}/custom/include
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mesp_decrypt/mesp_decrypt.c
    )
endif()

if ("${CONFIG_HISI_PRIVACY_PROTECTION}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/privacy_protection
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/msp_engine/include
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_PRIVACY_PROTECTION
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/privacy_protection/privacy_protection_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/privacy_protection/privacy_protection_syscall.c
    )
endif()

if ("${CONFIG_HISI_MSPC}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/p61
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/apdu
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/test
    )
    list(APPEND TEE_C_DEFINITIONS
        MSP_EXT_TPDU
        PLATFORM_NO_HISEE_FLAG
        CONFIG_HISI_MSPC
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/se_dummy.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/mspc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/mspc_ipc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/mspc_power.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/mspc_api.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/apdu/mspc_tpdu.c
    )
    if ("${TARGET_BUILD_VARIANT}" STREQUAL "eng")
        list(APPEND TEE_C_DEFINITIONS
            MSPC_DRIVER_TEST
        )
        list(APPEND TEE_C_SOURCES
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/test/mspc_test.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/test/mspc_test_performance.c
        )
        if ("${CONFIG_HISI_MSPC_IPC_TEST}" STREQUAL "true")
            list(APPEND TEE_C_DEFINITIONS
                CONFIG_HISI_MSPC_IPC_TEST
            )
            list(APPEND TEE_C_SOURCES
                ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mspc/test/mspc_ipc_test.c
            )
        endif()
    endif()
endif()

list(APPEND TEE_C_DEFINITIONS
    MODEM_SOCP_3_0
    CONFIG_HISI_MAILBOX
    CONFIG_SUPPORT_DMA_STATIC_ADDR
    CONFIG_SUPPORT_DMA_MOD_QOS_LEVEL
    TEE_SUPPORT_TZMP2
    CONFIG_HISI_SION_RECYCLE
    CONFIG_SOC_WE_WORKAROUND
    TEE_SUPPORT_SMMUV3
    DDR_FOUR_CHANNEL
    CONFIG_HISI_DDR_AUTO_FSGT
    CONFIG_HISI_DDR_SEC_HIFI_RESET
    CONFIG_HISI_DDR_CA_RD
    CONFIG_SUPPORT_ISP_LOAD
    TEE_SUPPORT_SECISP
    WITH_IMAGE_LOAD_SUPPORT
    CONFIG_DYNAMIC_MMAP_ADDR
    CONFIG_CHECK_PTN_NAME
    CONFIG_CHECK_PLATFORM_INFO
    CONFIG_HISI_SECBOOT_IMG_V2
    CONFIG_HISI_NVIM_SEC
    CONFIG_HISI_IVP_SEC_IMAGE
    CONFIG_SUPPORT_HIFI_LOAD
    CONFIG_DSS_TYPE_BALTIMORE
    CONFIG_HISI_EIIUS
    BALTIMORE_SFD_CONVERT
    CONFIG_SWING_20
    TEE_SUPPORT_HIVCODEC
    PLATFORM_NO_HISEE_FLAG
    SE_VENDOR_NXP
    HISI_TEE
    SE_SUPPORT_MULTISE
    SE_SUPPORT_SN110
    SE_SUPPORT_ST
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
