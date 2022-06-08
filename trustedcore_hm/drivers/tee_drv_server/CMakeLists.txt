set(ENTRY_POINT main)
include(apps_drv_flags)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    src/main.c
    src/drv_dispatch.c
    src/drv_fd_ops.c
    src/drv_process_mgr.c
    src/drv_index_mgr.c
    src/drv_ipc_mgr.c
    src/drv_pm.c
    src/drv_auth.c
    src/drv_dyn_conf_mgr.c
    src/drvcall_dyn_conf_mgr.c
    src/drv_dyn_policy_mgr.c
    src/base_drv_node.c
    ${PROJECT_SOURCE_DIR}/drivers/common/drv_pm_check.c
    src/task_mgr.c
)

list(APPEND TEE_C_FLAGS
    -Wno-implicit-fallthrough
)

if ("${CONFIG_LLVM_LTO}" STREQUAL "y")
    list(APPEND TEE_DRV_SERVER_FLAGS
        -flto -fsplit-lto-unit
    )
endif()

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_DRV_FD_DUMP
    )
endif()

if ("${CONFIG_DYN_CONF_DEBUG}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_DYN_CONF_DEBUG
    )
endif()

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND TEE TEE_C_DEFINITIONS
        CONFIG_TEE_MISC_DRIVER
    )
endif()

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        CRYPTO_MGR_SERVER_ENABLE
    )
endif()

list(APPEND TEE_C_DEFINITIONS TA_LOG_LEVEL=2)

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/ddk/hmapi
    ${PREBUILD_DIR}/headers/sys/hmapi
    ${PREBUILD_DIR}/headers/ddk/legacy
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/drivers/common
    ${PROJECT_SOURCE_DIR}/drivers/tee_drv_server/src
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdynconfmgr/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libspawn_common/include
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
)

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_DRV_SERVER_LIBRARIES
        hwi
        c_shared
        timer
        ac
        teemem
        teeos
        hmdrv
        spawn_common
    )
else()
    list(APPEND TEE_DRV_SERVER_LIBRARIES
        hwi_a32
        c_shared_a32
        timer
        ac_a32
        teemem_a32
        teeos_a32
        hmdrv_a32
        spawn_common_a32
    )
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_DRV_SERVER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared.so
    )
else()
    list(APPEND TEE_DRV_SERVER_LDFLAGS
        -Wl,-z,text
        -Wl,-z,noexecstack
        -Wl,--dynamic-linker=libc_shared_a32.so
    )
endif()

list(APPEND TEE_DRV_SERVER_LIBRARIES
    drv_frame
    ac_policy
    drv_shared
)

list(APPEND TEE_DRV_SERVER_WHOLE_ARCHIVE
    teeconfig
)

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TEE_DRV_SERVER_LDFLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${CONFIG_ENABLE_XOM32}" STREQUAL "y" AND "${ARCH}" STREQUAL "arm")
    list(APPEND TEE_DRV_SERVER_LDFLAGS
        -Wl,-T${XOM_LDS}
    )
endif()

set(TEE_CPP_FLAGS ${TEE_C_FLAGS})
set(TEE_CPP_INCLUDE_PATH ${TEE_INCLUDE_PATH})

list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/generic)
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_HEADER}/gen/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/hm)
list(REMOVE_ITEM TEE_CPP_FLAGS -I${PREBUILD_LIBC_INC}/arch/${ARCH}/bits)

list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/hm)
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/generic)
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_HEADER}/gen/arch/${ARCH})
list(REMOVE_ITEM TEE_CPP_INCLUDE_PATH ${PREBUILD_LIBC_INC}/arch/${ARCH}/bits)

list(FIND PRODUCT_APPS "tee_drv_server.elf" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

tee_add_executable(tee_drv_server.elf
    C_SOURCES
    ${TEE_C_SOURCES}

    CPP_SOURCES
    ${TEE_CPP_SOURCES}

    COMPILE_TOOL
    clang

    C_COMPILER_FLAGS
    ${TEE_C_FLAGS}
    ${TEE_CXX_FLAGS}
    ${TEE_DRV_SERVER_FLAGS}

    CPP_COMPILER_FLAGS
    ${TEE_CPP_FLAGS}
    ${TEE_CXX_FLAGS}
    ${TEE_DRV_SERVER_FLAGS}

    C_PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    CPP_PRIVATE_INCLUDES
    ${TEE_CPP_INCLUDE_PATH}

    C_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    CPP_COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    LD_FLAGS
    ${DRV_LDFLAGS}
    ${TEE_DRV_SERVER_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${CPP_LIBRARIES}
    ${TEE_DRV_SERVER_LIBRARIES}
    -lgcc

    WHOLEARCHIVE
    ${TEE_DRV_SERVER_WHOLE_ARCHIVE}

    INSTALL_DIR
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
