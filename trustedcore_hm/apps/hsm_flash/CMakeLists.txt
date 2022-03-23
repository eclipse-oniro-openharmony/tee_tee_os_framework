include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_hsm/src
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_common_client/src
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/libhsm_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libscmi/include
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/hm/TEE
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/inner_sdk/gpapi
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/hsm_upgrade
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/sfc
    ${PROJECT_SOURCE_DIR}/apps/include
)

list(APPEND TEE_C_SOURCES
    src/hsm_flash_ta.c
)

list(FIND PRODUCT_APPS "hsm_flash.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(hsm_flash.elf
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

    LD_FLAGS
    ${TA_LDFLAGS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
