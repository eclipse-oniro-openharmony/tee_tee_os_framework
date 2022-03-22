include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_shared/include
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
)

if ("${CONFIG_GATEKEEPER_32BIT}" STREQUAL "true" OR "${CONFIG_GATEKEEPER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_FLAGS
        -DSUPPORT_GATEKEEPER_TA
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/sys_apps/gatekeeper/src/task_gatekeeper
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

if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_SHARED_LIBS
        ccmgr
        crypto_hal
        timer
        agent
        agent_base
        hwi
        hmdrv
        teeos
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
        hwi_a32
        hmdrv_a32
        teeos_a32
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

if ("${CONFIG_RPMB_64BIT}" STREQUAL "true" OR "${CONFIG_RPMB_64BIT}" STREQUAL "false")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TEE_SHARED_LIBS
            rpmb
        )
    else()
        list(APPEND TEE_SHARED_LIBS
            rpmb_a32
        )
    endif()
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_SHARED_LIBS
        mbedtls
    )
elseif ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_SHARED_LIBS
        boringssl
    )
else()
    list(APPEND TEE_SHARED_LIBS
        openssl
    )
endif()

if ("${CONFIG_TUI_32BIT}" STREQUAL "true" OR "${CONFIG_TUI_64BIT}" STREQUAL "true")
    if ("${ARCH}" STREQUAL "aarch64")
        list(APPEND TEE_SHARED_LIBS
            tui
        )
    else()
        list(APPEND TEE_SHARED_LIBS
            tui_a32
        )
    endif()
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

if ("${ARCH}" STREQUAL "aarch64" AND "${CONFIG_ENABLE_XOM}" STREQUAL "y")
    list(APPEND TEE_SHARED_LINKER_FLAGS
        -Wl,-execute-only
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND TEE_SHARED_LINKER_FLAGS
        -Wl,-T${XOM_LIB_LDS}
    )
endif()

list(APPEND TEE_SHARED_LINKER_FLAGS
    -Wl,--defsym=faccess=tee_fs_faccess
    -Wl,--defsym=faccess2=tee_fs_faccess2
    -Wl,--defsym=fcreate=tee_fs_fcreate
    -Wl,--defsym=fopen=tee_fs_fopen
    -Wl,--defsym=fwrite=tee_fs_fwrite
    -Wl,--defsym=fread=tee_fs_fread
    -Wl,--defsym=fseek=tee_fs_fseek
    -Wl,--defsym=fclose=tee_fs_fclose
    -Wl,--defsym=finfo=tee_fs_finfo
    -Wl,--defsym=fremove=tee_fs_fremove
    -Wl,--defsym=ftruncate=tee_fs_ftruncate
    -Wl,--defsym=fsync=tee_fs_fsync
    -Wl,--defsym=frename=tee_fs_frename
    -Wl,--defsym=fcopy=tee_fs_fcopy
    -Wl,--defsym=ta_print=tee_print
    -Wl,--defsym=__SRE_HwiTrigger=SRE_HwiTrigger
    -Wl,--defsym=__SRE_HwiCreate=SRE_HwiCreate
    -Wl,--defsym=__SRE_HwiDelete=SRE_HwiDelete
    -Wl,--defsym=TEE_EXT_GetAgentBuffer=tee_get_agent_buffer
    -Wl,--defsym=ASM_Memcpy=asm_memcpy_ext
    -Wl,--defsym=_cfi_disabled=g_cfi_disabled
    -Wl,--defsym=cfi_disabled=g_cfi_disabled
)

set(TEE_PRECOMPILE_FLAGS ${TEE_C_FLAGS})
list(REMOVE_ITEM TEE_PRECOMPILE_FLAGS "-march=armv8-a")
foreach(d ${TEE_C_DEFINITIONS})
    list(APPEND TEE_PRECOMPILE_FLAGS -D${d})
endforeach()
add_custom_target(tee_shared_export)
add_custom_target(tee_shared_extern)
add_custom_command(
    TARGET tee_shared_export
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXPORT_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXPORT_FILE}
)
add_custom_command(
    TARGET tee_shared_extern
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXTERN_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXTERN_FILE}
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

tee_add_library(tee_shared SHARED
    SOURCES
    src/extra_syms.c
    src/se_ext.c
    src/libgcc_syms.c
    src/oemkey.c
    src/gk_auth_token.c

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
    add_dependencies(tee_shared tee_shared_export tee_shared_extern)
endif()
