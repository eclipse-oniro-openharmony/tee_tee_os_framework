include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/common/src/chip_info.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/efuse/efuse_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm_upgrade/hsm_update_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/scmi/scmi_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sec/sec_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_counter_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_crypto_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_efuse_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_kms_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_rpmb_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_counter_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_crypto_internal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_kms_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_verify_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/src/hsm_fuzz_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm_pg_info_get/hsm_pg_info_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sfc/sfc_lib.c
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/efuse
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sec/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/libhsm_client/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm_upgrade
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/src
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/efuse
	${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/ascend/sfc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/efuse
)

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_DEFINITIONS
        DEF_BUILDUSERMODE
    )
endif()

list(APPEND VENDOR_SHARED_LINKER_FLAGS
    -Wl,-shared
    -Wl,-X
    -Wl,-EL
    -Wl,-z,text
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,--gc-sections
    -L${PREBUILD_LIBS}/${ARCH}
    -nostdlib
    -Wl,-z,max-page-size=4096
)

list(FIND PRODUCT_APPS "vendor_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(vendor_shared SHARED
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

    LINKER_FLAGS
    ${CHOOSE_LLD}
    ${VENDOR_SHARED_LINKER_FLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${VENDOR_SHARED_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}

    LIBS_INSTALL_PATH
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(vendor_shared PROPERTIES OUTPUT_NAME "vendor_shared_a32")
endif()
