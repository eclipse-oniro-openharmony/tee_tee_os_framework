# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_C_SOURCES
    src/drv_share.c
    src/io_operations.c
)

if ("${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "false")
list(APPEND TEE_C_SOURCES
    src/tee_drv_entry.c
    src/drv_dispatch.c
    src/drv_operations.c
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/src/drv_thread.c
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/src/drv_param_ops.c
)

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "false")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_MGR_SERVER_ENABLE)
    list(APPEND TEE_C_SOURCES
        src/drv_random.c
    )
endif()

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_DRV_FD_DUMP
        TEE_SUPPORT_CMD_DUMP
    )
endif()
endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_SHARED_LIBS
        hwi
        c_shared
        teemem
        io
        teeconfig
    )
else()
    list(APPEND TEE_SHARED_LIBS
        hwi_a32
        c_shared_a32
        teemem_a32
        io_a32
        teeconfig
    )
endif()

set(EXTERN_FILE
    extern.txt
)
set(EXPORT_FILE
    export.txt
)

list(APPEND TEE_SHARED_LINKER_FLAGS
    -Wl,--shared
    -Wl,-X
    -Wl,-EL
    -Wl,-z,text
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/${EXPORT_FILE}
    -nostdlib
    -Wl,-z,max-page-size=4096
    -Wl,-L${PREBUILD_LIBS}/${ARCH}
    ${CMAKE_CURRENT_BINARY_DIR}/${EXTERN_FILE}
)

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_LIBC_INC}/arch/${ARCH}/bits
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libdrv_frame/include
)

if ("${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_DRV_SERVER_64BIT}" STREQUAL "false")
list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libspawn_common/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/drivers/common
)
endif()

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TEE_SHARED_LINKER_FLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${WITH_ENG_VERSION}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        TEE_SUPPORT_CMD_DUMP
    )
endif()


set(TEE_PRECOMPILE_FLAGS ${TEE_C_FLAGS})
list(REMOVE_ITEM TEE_PRECOMPILE_FLAGS "-march=armv8-a")
foreach(d ${TEE_C_DEFINITIONS})
    list(APPEND TEE_PRECOMPILE_FLAGS -D${d})
endforeach()
add_custom_target(drv_shared_export)
add_custom_target(drv_shared_extern)
add_custom_command(
    TARGET drv_shared_export
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXPORT_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXPORT_FILE}
)
add_custom_command(
    TARGET drv_shared_extern
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXTERN_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXTERN_FILE}
)

list(FIND PRODUCT_APPS "drv_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT clang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT clang_rt.builtins-aarch64)
endif()

tee_add_library(drv_shared SHARED
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

    LINKER_FLAGS
    ${CHOOSE_LLD}
    ${TEE_SHARED_LINKER_FLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${LINK_COMPILET_RT}

    LIBRARIES
    ${TEE_SHARED_LIBS}

    LIBS_INSTALL_PATH
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)

if ("${ARCH}" STREQUAL "arm")
    set_target_properties(drv_shared PROPERTIES OUTPUT_NAME "drv_shared_a32")
endif()

if ("${BUILD_TOOL}" STREQUAL "clang")
    add_dependencies(drv_shared drv_shared_export drv_shared_extern)
endif()
