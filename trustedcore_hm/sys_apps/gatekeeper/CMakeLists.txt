include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${DDK_INCLUDE_PATH_COMMON}
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/vendor/higeneric/libpincode/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_shared/include
)

list(APPEND TEE_C_SOURCES
    src/task_gatekeeper/gatekeeper.c
    src/task_gatekeeper/gatekeeper_fail_record.c
    src/task_gatekeeper/gatekeeper_auth_token.c
)

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(APPEND TEE_C_FLAGS
    -DGATEKEEPER_ITRATION_TIMES=${GATEKEEPER_ITRATION_TIMES}
    -DDERIVE_ROOT_INTERNAL_ITRATIONS=${DERIVE_ROOT_INTERNAL_ITRATIONS}
    )

list(FIND PRODUCT_APPS "gatekeeper.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(gatekeeper.elf
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
