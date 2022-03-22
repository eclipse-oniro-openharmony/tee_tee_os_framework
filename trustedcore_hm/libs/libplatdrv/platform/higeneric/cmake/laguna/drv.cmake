set(USE_GNU_CXX y)
set(COMPILE_SEC_DDR_TEST false)
list(APPEND PLATDRV_LIBRARIES
    bz_hm
)
# oemkey
include(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.cmake)

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
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include/platform/laguna
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/spi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/gpio
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i3c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/mailbox
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tzarch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/include
    ${PROJECT_SOURCE_DIR}/thirdparty/opensource/libbz_hm/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/isp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/revisions
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/ivp
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/bspatch/include/bsdiff
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/include/hifi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/eSE/hisee
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/video_decrypt
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem
)

list(APPEND TEE_C_DEFINITIONS
    MODEM_SOCP_3MODEM_SOCP_3_0
    CONFIG_HISI_MAILBOX
    TEE_SUPPORT_TZMP2
    CONFIG_HISI_SION_RECYCLE
    CONFIG_HISI_DDR_AUTO_FSGT
    CONFIG_HISI_DDR_SEC_HIFI_RESET
    CONFIG_HISI_SEC_DDR_SUB_RGN
    CONFIG_SUPPORT_ISP_LOAD
    WITH_IMAGE_LOAD_SUPPORT
    CONFIG_DYNAMIC_MMAP_ADDR
    CONFIG_CHECK_PTN_NAME
    CONFIG_CHECK_PLATFORM_INFO
    CONFIG_HISI_SECBOOT_IMG_V2
    CONFIG_HISI_NVIM_SEC
    CONFIG_HISI_IVP_SEC_IMAGE
    CONFIG_SUPPORT_HIFI_LOAD
    CONFIG_DSS_TYPE_LAGUNA
    SE_USE_ESE_I2C
    CONFIG_HISI_EIIUS
    TEE_SUPPORT_HIVCODEC
)

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SVM_DEBUG
    )
endif()

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i2c/i2c.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/i3c/i3c.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/spi/spi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/mailbox/ipc_mailbox.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/gpio/gpio.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tzpc/tzpc_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/seccfg/hisi_hwspinlock.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/iommu/siommu.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/genalloc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/lib/bitmap.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sion/sion_recycling.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/laguna_ddr_autofsgt_proxy_secure_os.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/laguna/sec_region.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/laguna/tzmp2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/isp/revisions/hisp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ivp/hivp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secureboot_v2.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/secboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_hifi_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_isp_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/process_ivp_info.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hifi/hifi_reload.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_disp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_fb_sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_overlay_utils.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/display2.0/hisi_dss_module_registe.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/hisi_disp.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/hisi_fb_sec.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/hisi_overlay_utils.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/hisi_dss_module_registe.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_dfc/hisi_dss_dfc_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_dma/hisi_dss_dma_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_ldi/hisi_dss_ldi_kirin990_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_mctl/hisi_dss_mctl_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_mif/hisi_dss_mif_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_mix/hisi_dss_mix_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_ovl/hisi_dss_ovl_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/reg_smmu/hisi_dss_smmu_kirin980_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrvplatform/common/display2.0/channel_data/hisi_dss_channel_data_denver_base.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secureboot/eiius_interface.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry/sec_ufs_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry/sec_derive_key.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/file_encry/sec_ufs_key_drv.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/tee_sharedmem/bl2_sharedmem.c
)
if ("${COMPILE_SEC_DDR_TEST}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/secmem/driver/sec/laguna/sec_region_test.c
    )
    list(APPEND TEE_C_DEFINITIONS
        CONFIG_HISI_SEC_DDR_TEST
    )
endif()

if ("${CONFIG_DX_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        DX_ENABLE=1
    )
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
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/platform/common/cc_driver
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/platform/common/cc_driver/cc712
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc712/cc_driver_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_adapt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/ccdriver_lib/cc_power.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/antiroot/nonsecure_hasher.c
    )
endif()

if ("${FEATURE_HISI_HIEPS}" STREQUAL "true")
    set(SEC_DFT_ENABLE ${WITH_ENG_VERSION})
    set(SEC_PRODUCT ${TARGET_BOARD_PLATFORM})
    set(PROJECT_ROOT_DIR ${PROJECT_SOURCE_DIR}/libs/libplatdrv)
    # add_subdirectory(${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hieps)
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/kirin/hieps/include
    )
endif()
