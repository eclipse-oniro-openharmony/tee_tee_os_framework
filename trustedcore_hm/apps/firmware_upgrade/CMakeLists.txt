include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_hsm/src/
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_common_client/src
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/hm/TEE
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/efuse
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/hsm_upgrade
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/libhsm_client/include
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/scmi
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/sec
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/apps/include
)

list(APPEND TEE_C_SOURCES
    src/firmware_upgrade.c
    src/firmware_upgrade_ta.c
    src/firmware_upgrade_api.c
    src/firmware_upgrade_ta_api.c
)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "firmware_upgrade.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(firmware_upgrade.elf
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
