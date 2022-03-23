include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DCC_DRIVER
    -Wall
    -DSECFLASH_PARTITION_HIGH_HALF_ENABLE
)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src/
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_common_client/src
    ${PROJECT_SOURCE_DIR}/sys_libs/libhsm_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libhsm_client/src
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/efuse
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/hsm_upgrade
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/scmi
    ${PROJECT_SOURCE_DIR}/vendor/ascend/libvendor_shared/src/sec
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PROJECT_SOURCE_DIR}/prebuild/hm-teeos-release/headers/sdk/gpapi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/apps/hsm/include
    ${DDK_INCLUDE_PATH_COMMON}
)

list(APPEND TEE_C_SOURCES
    src/hsm_common.c
    src/hsm_counter.c
    src/hsm_crypto.c
    src/hsm_efuse.c
    src/hsm_km.c
    src/hsm_rpmb.c
    src/hsm_service.c
    src/hsm_verify.c
    src/hsm_service_fuzz.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND HSM_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND HSM_LIBRARIES
        teeagentcommon
        teeagentcommon_client
    )
else()
    list(APPEND HSM_LIBRARIES
        teeagentcommon
        teeagentcommon_client
    )
endif()

list(FIND PRODUCT_APPS "hsm.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(hsm.elf
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
    ${HSM_LDFLAGS}

    LINKGROUP
    ${HSM_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
