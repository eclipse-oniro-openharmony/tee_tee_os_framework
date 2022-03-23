set(SVC_PARTITIAL_LINK y)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_SOURCES
    src/tee_fs_oper_config.c
    src/tee_secflash_oper_config.c
)
if (NOT "${CONFIG_TEE_FS_OPER}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DTEE_FS_OPER
    )
endif()
if ("${CONFIG_DC_SECFLASH}" STREQUAL "y")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND SSA_LIBRARIES
            sec_fs
            zlib
        )
    else()
        list(APPEND SSA_LIBRARIES
            sec_fs_a32
            zlib_a32
        )
    endif()
endif()
if ("${CONFIG_SECFS_SECFLASH}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_SECFS_SECFLASH
    )
endif()
if ("${CONFIG_MERGE_HUK_SSA}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/framework/huk_service/src/huk_service_config.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/framework/huk_service/include
    )
endif()
list(APPEND TEE_INCLUDE_PATH
    ${PLATFORM_DIR}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
)

if ("${CONFIG_DYNLINK}" STREQUAL "y")
    list(APPEND SSA_LDFLAGS
        -Wl,--entry=tee_task_entry
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND SSA_LIBRARIES
        ssagent
    )
else()
    list(APPEND SSA_LIBRARIES
        ssagent_a32
    )
endif()

list(FIND PRODUCT_APPS "ssa.elf" index)
if (${index} GREATER -1)
	if ("${CONFIG_SSA_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_SSA_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

tee_add_executable(ssa.elf
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
    ${DRV_LDFLAGS}
    ${SSA_LDFLAGS}

    LIBRARIES
    ${SSA_LIBRARIES}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
