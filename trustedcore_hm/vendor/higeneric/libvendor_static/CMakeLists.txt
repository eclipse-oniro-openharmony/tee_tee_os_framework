include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/chip_info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/extra_syms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/hdcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/hisi_mspc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/inse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/secboot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/secflash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/file_encry_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/fp_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/fr_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_hieps_task.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_privacy_protection_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/hisi_secboot_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/npu_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/secmem_drv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/driver_api/vdecry_drv.c
    ${PROJECT_SOURCE_DIR}/vendor/common/src/chip_info.c
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client/src/sec_flash_api.c
)

if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../libvendor_shared/src/se_status.c
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libvltmm_a32/include
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libsec_flash_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_FLAGS
        -DDEF_BUILDUSERMODE
    )
endif()

if ("${CONFIG_HISI_MSPC_IPC_TEST}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_HISI_MSPC_IPC_TEST
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

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
