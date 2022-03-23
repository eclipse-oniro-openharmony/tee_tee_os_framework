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
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include/
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/mtk
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/spi/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/gpio/inc
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap
)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/mtk/cc_driver_adapt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/ccdriver_lib/mtk_adapt.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/cc_driver/cc_driver_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/ccdriver_lib/cc_driver_syscall.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/secboot/secureboot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/spi/spi_mtk.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/fingerprint/src/tee_fingerprint.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/gpio/gpio_mtk.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/antiroot/nonsecure_hasher.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/antiroot/sre_rwroot.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/gatekeeper/key_factor.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/plat_cap/plat_cap_hal.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/mtk/eSE/se_syscall.c
    )
endif()
