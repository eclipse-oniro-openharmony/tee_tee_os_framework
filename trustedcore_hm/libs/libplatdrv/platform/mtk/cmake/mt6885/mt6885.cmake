list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/ccdriver_lib/include
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/crys/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/driver/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/host/src/cc710teelib/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rsa/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/utils/src/common/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rnd_dma/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/pki/pka/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/common/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/api/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/fips/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/proj/cc710tee/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/ecc/ecc_domains/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/
    ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/hmos/
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/kernel
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/mtk
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/spi/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/touchscreen
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/gpio/inc
    ${PROJECT_SOURCE_DIR}/platform/mtk/phone/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
)

if ("${CONFIG_M_DRIVER}" STREQUAL "true")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/drv_pal/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/dynion/include
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/drv_pal/src/drv_fwk.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/drv_pal/src/secmem_core_api.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/dynion/src/dynion.c
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/dynion/src/dynion_config.c
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/file_encry_v2
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/t1
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/spi_common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/spm
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/utils
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/pal/spi
)

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/mbedtls
    )
elseif ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/boringssl
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/openssl
        ${PREBUILD_DIR}/headers/openssl/openssl
        ${PREBUILD_DIR}/headers/openssl/crypto
    )
endif()

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/mtk/cc_driver_adapt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/ccdriver_lib/mtk_adapt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/ccdriver_lib/cc_driver_syscall.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/secboot/secureboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/spi/spi_mtk.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/fingerprint/src/tee_fingerprint.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/touchscreen/tui_touchscreen_panel.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/touchscreen/tui_touchscreen_platform.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/touchscreen/panel/tui_synaptics.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/touchscreen/panel/tui_gtx8.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/gpio/gpio_mtk.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/antiroot/nonsecure_hasher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/antiroot/sre_rwroot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/file_encry_v2/sec_fbe2_km.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/file_encry_v2/sec_fbe2_ufsc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/se_dummy.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/atf/atf.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/t1/t1.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/spi_common/spi_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/p73.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/pal/spi/phNxpEsePal_spi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/pal/phNxpEsePal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib/phNxpEse_Api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib/phNxpEse_Api_hisi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib/phNxpEse_Apdu_Api.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib/phNxpEseDataMgr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/lib/phNxpEseProto7816_3.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/utils/ese_config_hisi.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/p73/utils/ringbuffer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/drv_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/mem_cfg.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/tui_drv.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/tui_drv/tui_timer.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/touchscreen/tui_touchscreen.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/gatekeeper/key_factor.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)

set(DISP_COMMON_INC_PATH ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/tui)
set(DISP_MT6885_INC_PATH ${DISP_COMMON_INC_PATH}/mt6885)
set(DISP_INC_PATH ${DISP_MT6885_INC_PATH}/platforms/display/mt6885)
set(CMDQ_INC_PATH ${DISP_MT6885_INC_PATH}/platforms/cmdq)
set(M4U_INC_PATH ${DISP_MT6885_INC_PATH}/platforms/m4u)
set(GENERIC_PATH ${DISP_MT6885_INC_PATH}/platforms/generic)

list(APPEND TEE_INCLUDE_PATH
    ${DISP_MT6885_INC_PATH}
    ${DISP_MT6885_INC_PATH}/platforms/generic
    ${DISP_MT6885_INC_PATH}/inc
    ${DISP_INC_PATH}/include
    ${CMDQ_INC_PATH}
    ${M4U_INC_PATH}
)

list(APPEND TEE_C_SOURCES
    ${DISP_COMMON_INC_PATH}/dr_api.c
    ${DISP_MT6885_INC_PATH}/platforms/generic/mtk_log.c
    ${DISP_INC_PATH}/display_tui.c
    ${DISP_INC_PATH}/ddp_drv.c
    ${DISP_INC_PATH}/ddp_info.c
    ${DISP_INC_PATH}/ddp_debug.c
    ${DISP_INC_PATH}/ddp_path.c
    ${DISP_INC_PATH}/ddp_rdma.c
    ${DISP_INC_PATH}/ddp_dsi.c
    ${DISP_INC_PATH}/ddp_dump.c
    ${DISP_INC_PATH}/ddp_color_format.c
    ${DISP_INC_PATH}/ddp_ovl.c
    ${DISP_INC_PATH}/display_tui_hal.c
    ${CMDQ_INC_PATH}/cmdq_sec_record.c
    ${CMDQ_INC_PATH}/cmdq_sec_core.c
    ${CMDQ_INC_PATH}/cmdq_sec_platform.c
    ${M4U_INC_PATH}/tui_m4u.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/se_syscall.c
    )
endif()

list(APPEND TEE_C_DEFINITIONS
    MTK_ESE
    SE_SUPPORT_ST
    SE_VENDOR_NXP
    SE_SUPPORT_MULTISE
    SE_SUPPORT_SN110
)
