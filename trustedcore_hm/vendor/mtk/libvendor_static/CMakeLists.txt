include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/chip_info.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/extra_syms.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/hdcp.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/inse.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/secboot.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/driver_api/fp_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/driver_api/fr_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/driver_api/hisi_secboot_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/driver_api/secmem_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/driver_api/vdecry_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/chip_info.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/vendor/mtk/libvendor_shared/src/se_status.c
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_DEFINITIONS
        DEF_BUILDUSERMODE
    )
endif()

tee_add_library(vendor_static STATIC
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
