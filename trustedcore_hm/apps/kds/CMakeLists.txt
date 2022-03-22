include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DARM_PAE=1
)

list(APPEND TEE_C_SOURCES
    src/task_kds/kds.c
    src/task_kds/kds_core.c
    src/task_kds/kds_phase1.c
    src/task_kds/kds_phase2.c
    src/task_kds/kds_phase3.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/vendor/common/include
)

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

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

list(FIND PRODUCT_APPS "kds.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(kds.elf
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
