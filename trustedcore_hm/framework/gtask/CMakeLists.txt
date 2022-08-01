set(ENTRY_POINT main)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

if ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "1")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V3
    )
elseif ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "2")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V3
    )
elseif ("${CONFIG_DYN_TA_FORMAT}" STREQUAL "3")
    list(APPEND TEE_C_FLAGS
        -DDYN_TA_SUPPORT_V3
    )
else()
    message(FATAL_ERROR "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif()

if ("${CONFIG_PUBKEY_SHAREMEM}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_PUBKEY_SHAREMEM
    )
endif()

list(APPEND TEE_C_SOURCES
    src/gtask_para_config.c
    src/tee_task_config.c
    src/gtask_config_hal.c
    src/gtask_config.c
)

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PLATFORM_DIR}/common/include
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/common/tee_config
    ${PLATFORM_DIR}/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/gtask/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeagentcommon_client/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/src/tee_config
)

if ("${CONFIG_HUANGLONG_LOAD_KEY_3072}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/src/huanglong/ecies_keys
    )
endif()

if ("${product_type}" STREQUAL "cdc")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_CDC
    )
elseif ("${product_type}" STREQUAL "cdc_ace")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_CDC
    )
elseif ("${product_type}" STREQUAL "mdc")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_MDC
    )
elseif ("${product_type}" STREQUAL "mini")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_MINI
    )
elseif ("${CONFIG_TA_SIGN_KEY_CBG}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_CBG
    )
elseif ("${CONFIG_TA_LOCAL_SIGN}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DTA_LOCAL_SIGN
    )
elseif ("${CONFIG_HUANGLONG_LOAD_KEY_3072}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DCONFIG_TA_SIGN_HUANGLONG
    )
endif()

list(APPEND TEE_C_FLAGS
    -fstack-protector-all
)

if ("${CONFIG_PLAT_HUANGLONG}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/platform/huanglong/ta_load/tee_ta_load.c
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND GTASK_LIBRARIES
        gtask
        c_shared
        tee_shared
        base_shared
        permission_service
        teemem
        hmdrv
        ac
        teeconfig
        ac_policy
        dynconfmgr
        dynconfbuilder
        spawn_common
    )
    if (NOT ("${CONFIG_APP_TEE_PERM}" STREQUAL "y" OR "${CONFIG_APP_TEE_PERM_A32}" STREQUAL "y"))
        list(APPEND GTASK_LIBRARIES elf_verify elf_verify_key whitebox)
    endif()
else()
    list(APPEND GTASK_LIBRARIES
        gtask_a32
        c_shared_a32
        base_shared
        permission_service_a32
        teemem_a32
        hmdrv_a32
        ac_a32
        teeconfig
        ac_policy
        dynconfmgr
        dynconfbuilder
        spawn_common
    )
    if (NOT ("${CONFIG_APP_TEE_PERM}" STREQUAL "y" OR "${CONFIG_APP_TEE_PERM_A32}" STREQUAL "y"))
        list(APPEND GTASK_LIBRARIES elf_verify_a32 elf_verify_key whitebox_a32)
    endif()
endif()

if (NOT "${CONFIG_NO_VENDOR_LIB_EMBEDDED}" STREQUAL "true")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND GTASK_LIBRARIES
            vendor_static
        )
    else()
        list(APPEND GTASK_LIBRARIES
            vendor_static
        )
    endif()
endif()

if ("${CONFIG_TERMINAL_DRV_SUPPORT}" STREQUAL "y")
    list(APPEND GTASK_LIBRARIES
        devchip_api
    )
endif()

list(APPEND GTASK_LDFLAGS
    -Wl,-z,text
    -Wl,-z,noexecstack
)
if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND GTASK_LDFLAGS
        -Wl,--dynamic-linker=libc_shared.so
    )
else()
    list(APPEND GTASK_LDFLAGS
        -Wl,--allow-shlib-undefined
        -Wl,--dynamic-linker=libc_shared_a32.so
        ../../sys_libs/libtee_shared/libtee_shared_a32.so
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS "-flto")
list(REMOVE_ITEM TEE_C_FLAGS "-fsplit-lto-unit")

list(FIND PRODUCT_APPS "gtask.elf" index)
if (${index} GREATER -1)
    if ("${CONFIG_GTASK_64BIT}" STREQUAL "true" AND "${ARCH}" STREQUAL "aarch64")
        set(IF_INSTALL DO_INSTALL)
    endif()
    if ("${CONFIG_GTASK_64BIT}" STREQUAL "false" AND "${ARCH}" STREQUAL "arm")
        set(IF_INSTALL DO_INSTALL)
    endif()
endif()

tee_add_executable(gtask.elf
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
    ${GTASK_LDFLAGS}

    LINKGROUP
    ${GTASK_LIBRARIES}
    ${COMMON_LIBGCC_COMPS}
    ${COMMON_LDFLAGS}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)

if ("${ARCH}" STREQUAL "arm")
    add_dependencies(gtask.elf tee_shared base_shared)
endif()
