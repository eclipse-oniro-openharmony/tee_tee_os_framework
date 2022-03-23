include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND SE_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND SE_SERVICE_LIBRARIES
        sesrv
    )
else()
    list(APPEND SE_SERVICE_LIBRARIES
        sesrv_a32
    )
endif()

list(FIND PRODUCT_APPS "se_service.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_SE_SERVICE_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

tee_add_executable(se_service.elf
    SOURCES
    src/sesrv_permission_config.c

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
    ${SE_SERVICE_LDFLAGS}

    LIBRARIES
    ${SE_SERVICE_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
