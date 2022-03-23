include(apps_ta_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${DDK_INCLUDE_PATH_COMMON}
)

list(APPEND TEE_C_SOURCES
    src/task_storage/storage_task.c
)
if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/sys_libs/libta_magic_a32/src/ta_magic.c
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND STORAGE_LIBRARIES
)
else()
    list(APPEND STORAGE_LIBRARIES
)
endif()

list(FIND PRODUCT_APPS "storage.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(storage.elf
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

    LIBRARIES
    ${STORAGE_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
