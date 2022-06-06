include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_shared/include
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
    ${PROJECT_SOURCE_DIR}/libs/syslib/libmmgr/include
    ${PREBUILD_HEADER}/sys/mmgr
    ${PREBUILD_HEADER}/sys/mmgr_sysmgr
)

if ("${CONFIG_GATEKEEPER_32BIT}" STREQUAL "true" OR "${CONFIG_GATEKEEPER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS -DSUPPORT_GATEKEEPER_TA)
    set(TEE_SHARED_SRCS
        ${TEE_SHARED_SRCS}
        src/gk_auth_token.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_apps/gatekeeper/src/task_gatekeeper
    )
else()
    set(TEE_SHARED_SRCS
        ${TEE_SHARED_SRCS}
        src/gk_auth_token_stub.c
    )
endif()

if ("${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "true" OR "${CONFIG_TEE_MISC_DRIVER_64BIT}" STREQUAL "false")
    list(APPEND TEE TEE_C_DEFINITIONS
        CONFIG_TEE_MISC_DRIVER
    )
endif()

if ("${TARGET_BUILD_VARIANT}" STREQUAL "user")
    list(APPEND TEE_C_FLAGS
        -DDEF_BUILDUSERMODE
    )
endif()

if ("${CONFIG_EXPORT_OPENSSL_SYMBOL}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DSUPPORT_EXPORT_OPENSSL_SYMBOL
    )
endif()

 if ("${CONFIG_DYN_IMPORT_CERT}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DDYN_IMPORT_CERT=1
    )
 endif()

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_SHARED_LIBS
        ccmgr
        crypto_hal
        timer
        agent
        agent_base
        hmdrv
        teeos
        permission_service
        swcrypto_engine
        taentry
        teeagentcommon_client
        crypto
        teeconfig
        teemem
        ac
        ac_policy
        decouple
        ssa
        huk
        sec_fs_msg
        teedynsrv
    )
else()
    list(APPEND TEE_SHARED_LIBS
        ccmgr
        crypto_hal
        timer
        agent_a32
        agent_base_a32
        hmdrv_a32
        teeos_a32
        permission_service_a32
        swcrypto_engine
        taentry_a32
        teeagentcommon_client
        crypto_a32
        teeconfig
        teemem_a32
        ac_a32
        ac_policy
        decouple_a32
        ssa_a32
        huk_a32
        sec_fs_msg_a32
        teedynsrv
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_SHARED_LIBS
        mbedtls
    )
else()
    list(APPEND TEE_SHARED_LIBS
        openssl
    )
endif()

if ("${CONFIG_OTRP_SUPPORT}" STREQUAL "y")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TEE_SHARED_LIBS
            otrp
        )
    else()
        list(APPEND TEE_SHARED_LIBS
            otrp_a32
        )
    endif()
endif()

if ("${CONFIG_SEM}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_32BIT}" STREQUAL "true" OR "${CONFIG_SE_SERVICE_64BIT}" STREQUAL "true")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TEE_SHARED_LIBS
            se
        )
    else()
        list(APPEND TEE_SHARED_LIBS
            se_a32
        )
    endif()
endif()

if ("${CONFIG_LIBTEE_SHARED_LITE}" STREQUAL "y")
    set(EXTERN_FILE
        lite_extern.txt
    )
    set(EXPORT_FILE
        lite_export.txt
    )
    set(ALIAS_FILE
        lite_alias.txt
    )
elseif("${CONFIG_OH_SHARED_LIB}" STREQUAL "y")
    set(EXTERN_FILE
        oh_extern.txt
    )
    set(EXPORT_FILE
        oh_export.txt
    )
    set(ALIAS_FILE
        oh_alias.txt
    )
else()
    set(EXTERN_FILE
        extern.txt
    )
    set(EXPORT_FILE
        export.txt
    )
    set(ALIAS_FILE
        alias.txt
    )
endif()

execute_process(
    COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/${ALIAS_FILE}
    COMMAND awk "{ print \"-Wl,--defsym=\"$$1 }"
    COMMAND tr "\n" " "
    OUTPUT_VARIABLE ALIAS_SYM
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
    ${ALIAS_SYM}
)

if(NOT "${CMAKE_TOOLCHAIN_BASEVER}" STREQUAL "8.0.1")
    list(APPEND TEE_SHARED_LINKER_FLAGS
        -Wl,-z,separate-loadable-segments
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND TEE_SHARED_LINKER_FLAGS
        -Wl,-T${XOM_LIB_LDS}
    )
endif()

set(TEE_PRECOMPILE_FLAGS ${TEE_C_FLAGS})
list(REMOVE_ITEM TEE_PRECOMPILE_FLAGS "-march=armv8-a")
foreach(d ${TEE_C_DEFINITIONS})
    list(APPEND TEE_PRECOMPILE_FLAGS -D${d})
endforeach()
add_custom_target(tee_shared_export)
add_custom_target(tee_shared_extern)
add_custom_target(tee_shared_alias)
add_custom_command(
    TARGET tee_shared_export
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXPORT_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXPORT_FILE}
)
add_custom_command(
    TARGET tee_shared_extern
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXTERN_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXTERN_FILE}
)
add_custom_command(
    TARGET tee_shared_alias
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${ALIAS_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${ALIAS_FILE}
)

list(FIND PRODUCT_APPS "tee_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT clang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT clang_rt.builtins-aarch64)
endif()

set(TEE_SHARED_SRCS
    ${TEE_SHARED_SRCS}
    src/extra_syms.c
    src/se_ext.c
    src/libgcc_syms.c
    src/oemkey.c
)

tee_add_library(tee_shared SHARED
    SOURCES
    ${TEE_SHARED_SRCS}

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
    set_target_properties(tee_shared PROPERTIES OUTPUT_NAME "tee_shared_a32")
endif()

if ("${BUILD_TOOL}" STREQUAL "clang")
    add_dependencies(tee_shared tee_shared_export tee_shared_extern tee_shared_alias)
endif()
