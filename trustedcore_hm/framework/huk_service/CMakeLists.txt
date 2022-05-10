include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PLATFORM_DIR}/common/include
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND HUK_SERVICE_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${CONFIG_HUK_PLAT_COMPATIBLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_HUK_PLAT_COMPATIBLE
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND HUK_SERVICE_LIBRARIES
        huksrv
    )
else()
    list(APPEND HUK_SERVICE_LIBRARIES
        huksrv_a32
    )
endif()

list(FIND PRODUCT_APPS "huk_service.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_HUK_SERVICE_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_HUK_SERVICE_32BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

tee_add_executable(huk_service.elf
    SOURCES
    src/huk_service_config.c

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
    ${HUK_SERVICE_LDFLAGS}

    LIBRARIES
    ${HUK_SERVICE_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
