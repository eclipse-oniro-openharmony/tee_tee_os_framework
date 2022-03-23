include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DSM_SUPPORT
    -DOPENSSL_NO_STDIO
)

list(APPEND GM_SHARED_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/libplatdrv/platform/common/crypto
    ${PREBUILD_DIR}/headers/gmssl
    ${PREBUILD_DIR}/headers/gmssl/crypto/ec
    ${PREBUILD_DIR}/headers/gmssl/crypto/bn
    ${PREBUILD_DIR}/headers/gmssl/crypto/include
    ${PREBUILD_DIR}/headers/gmssl/crypto/sm2
    ${PREBUILD_DIR}/headers/gmssl/crypto/sm4
)

list(APPEND TEE_C_SOURCES
    src/gmssl_api.c
)

list(APPEND LIBGM_SHARED_LDFLAGS
    -Wl,-shared
    -Wl,-X
    -Wl,-EL
    -Wl,-z,text
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,max-page-size=4096
    -Wl,-L${PREBUILD_LIBS}/${ARCH}
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/export.txt
    -nostdlib
    ${CMAKE_CURRENT_SOURCE_DIR}/extern.txt
)

if ("${ARCH}" STREQUAL "aarch64" AND "${CONFIG_ENABLE_XOM}" STREQUAL "y")
    list(APPEND LIBGM_SHARED_LDFLAGS
        -Wl,-execute-only
    )
endif()

if ("${ARCH}" STREQUAL "arm" AND "${CONFIG_ENABLE_XOM32}" STREQUAL "y")
    list(APPEND LIBGM_SHARED_LDFLAGS
        -Wl,-T${XOM_LIB_LDS}
    )
endif()

list(FIND PRODUCT_APPS "gm_shared" index)
if (${index} GREATER -1)
    set(IF_INSTALL DO_INSTALL)
endif()

if("${ARCH}" STREQUAL "arm")
set(LINK_COMPILET_RT clang_rt.builtins-arm)
else()
set(LINK_COMPILET_RT clang_rt.builtins-aarch64)
endif()
if ("${ARCH}" STREQUAL "aarch64")
    list(APPEND TEE_C_FLAGS
         -march=armv8-a
        )
else()
    list(REMOVE_ITEM TEE_C_FLAGS -march=armv8-a)
    list(APPEND TEE_C_FLAGS -march=armv7ve)
endif()
tee_add_library(gm_shared SHARED
    SOURCES
    ${TEE_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${GM_SHARED_INCLUDE_PATH}
    ${TEE_INCLUDE_PATH}

    LINKER_FLAGS
    ${CHOOSE_LLD}
    ${LIBGM_SHARED_LDFLAGS}
    ${COMMON_LDFLAGS}

    LINKGROUP
    gmssl
    ${LINK_COMPILET_RT}

    LIBS_INSTALL_PATH
    ${BOOTFS_STAGE_DIR}

    ${IF_INSTALL}
)
if ("${ARCH}" STREQUAL "arm")
    set_target_properties(gm_shared PROPERTIES OUTPUT_NAME "gm_shared_a32")
endif()
