include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_C_FLAGS
        -DARM_PAE=1
        -DCC_DRIVER=1
    )
else()
    list(APPEND TEE_C_FLAGS
        -DARM_PAE=1
        -mfloat-abi=softfp
        -mfpu=neon
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src/task_bdkernel
)

list(APPEND TEE_C_SOURCES
    src/task_bdkernel/bdkernel_ta.c
    src/task_bdkernel/bdkernel_kdf.c
    src/task_bdkernel/bdkernel_utils.c
    src/task_bdkernel/bdkernel_handler.c
    src/task_bdkernel/bdkernel_hardware.c
    src/task_bdkernel/bdkernel_initialize.c
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

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

list(FIND PRODUCT_APPS "bdkernel.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(bdkernel.elf
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
