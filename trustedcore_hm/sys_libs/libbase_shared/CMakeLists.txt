include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/platform/common/tee_config
)

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
    list(APPEND BASE_SHARED_LIBS
        c_shared
        hmlog
        timer
    )
else()
    list(APPEND BASE_SHARED_LIBS
        c_shared_a32
        hmlog_a32
        timer
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND BASE_SHARED_LIBS
        mbedtls
    )
elseif ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND BASE_SHARED_LIBS
        boringssl
    )
else()
    list(APPEND BASE_SHARED_LIBS
        openssl
    )
endif()

set(EXTERN_FILE
    extern.txt
)

set(EXPORT_FILE
    export.txt
)

set(ALIAS_FILE
    alias.txt
)

list(APPEND BASE_SHARED_LINKER_FLAGS
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
    list(APPEND BASE_SHARED_LINKER_FLAGS
        -Wl,-execute-only
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND BASE_SHARED_LINKER_FLAGS
        -Wl,-T${XOM_LIB_LDS}
    )
endif()

set(TEE_PRECOMPILE_FLAGS ${TEE_C_FLAGS})
list(REMOVE_ITEM TEE_PRECOMPILE_FLAGS "-march=armv8-a")
foreach(d ${TEE_C_DEFINITIONS})
    list(APPEND TEE_PRECOMPILE_FLAGS -D${d})
endforeach()
add_custom_target(base_shared_export)
add_custom_target(base_shared_extern)
add_custom_command(
    TARGET base_shared_export
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXPORT_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXPORT_FILE}
)
add_custom_command(
    TARGET base_shared_extern
    COMMAND ${CMAKE_C_COMPILER} ${TEE_PRECOMPILE_FLAGS} --target=${triple} -x assembler-with-cpp -E --no-line-commands ${CMAKE_CURRENT_SOURCE_DIR}/${EXTERN_FILE} -o ${CMAKE_CURRENT_BINARY_DIR}/${EXTERN_FILE}
)

list(FIND PRODUCT_APPS "base_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT clang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT clang_rt.builtins-aarch64)
endif()

tee_add_library(base_shared SHARED
    SOURCES
    src/extra_syms.c

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
    ${BASE_SHARED_LINKER_FLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    ${LINK_COMPILET_RT}

    LIBRARIES
    ${BASE_SHARED_LIBS}

    LIBS_INSTALL_PATH
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(base_shared PROPERTIES OUTPUT_NAME "base_shared_a32")
endif()

if ("${BUILD_TOOL}" STREQUAL "clang")
    add_dependencies(base_shared base_shared_export base_shared_extern)
endif()
