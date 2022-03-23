include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/libbiometric_a32/include
    ${PROJECT_SOURCE_DIR}/libs/libmspcore_a32/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
)

list(APPEND TEE_C_SOURCES
    src/biometric_msg.c
    src/biometric_task.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND BIOMETRIC_LDFLAGS
        -Wl,--entry=tee_task_entry
        -s
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND BIOMETRIC_LIBRARIES
        teeagentcommon
        mspcore
    )
else()
    list(APPEND BIOMETRIC_LIBRARIES
        teeagentcommon
        mspcore
    )
endif()

list(FIND PRODUCT_APPS "biometric.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(biometric.elf
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
    ${BIOMETRIC_LDFLAGS}

    LINKGROUP
    ${BIOMETRIC_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
