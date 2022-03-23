include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DCC_DRIVER=1
    -Wall
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon/src
    ${PROJECT_SOURCE_DIR}/libs/librot/include
    ${PROJECT_SOURCE_DIR}/libs/libmspcore_a32/include
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
)

list(APPEND TEE_C_SOURCES
    src/rot_msg.c
    src/rot_task.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND ROT_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND ROT_LIBRARIES
        teeagentcommon
    )
else()
    list(APPEND ROT_LIBRARIES
        teeagentcommon
    )
endif()

list(FIND PRODUCT_APPS "rot.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(rot.elf
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
    ${ROT_LDFLAGS}

    LINKGROUP
    ${ROT_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
