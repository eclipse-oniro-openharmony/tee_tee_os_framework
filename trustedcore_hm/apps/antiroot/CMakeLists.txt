include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -Wdate-time
    -Wfloat-equal
    -Wshadow
    -Wformat=2
    -Wstack-protector
    -fsigned-char
    -fno-common
    -fno-strict-aliasing
    -D_FORTIFY_SOURCE=2
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_antiroot
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_antiroot/eima
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
)

list(APPEND TEE_C_SOURCES
    src/task_antiroot/eima_ta.c
    src/task_antiroot/antiroot_task.c
    src/task_antiroot/eima/eima_task.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(FIND PRODUCT_APPS "antiroot.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_executable(antiroot.elf
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
