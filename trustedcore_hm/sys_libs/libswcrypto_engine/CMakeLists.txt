add_custom_target(libswcrypto_engine_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_C_FLAGS
    -DARM_PAE=1
    -D__ARM_ARCH_=7
    -DTARGET_PRODUCT_VAL=\"${TARGET_BOARD_PLATFORM}\"
)
if ("${CONFIG_CRYPTO_MIX_SYSTEM}" STREQUAL "y")
    list(APPEND TEE_C_DEFINITIONS SWCRYPTO_MIX_SYSTEM)
endif()

if ("${CONFIG_CRYPTO_SUPPORT_X509}" STREQUAL "true")
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/create_cert_wrapper.c
        src/tee_ext_cert_api.c
        src/x509_wrapper.c
    )
else()
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/stub/create_cert_wrapper_stub.c
        src/stub/tee_ext_cert_api_stub.c
        src/stub/x509_wrapper_stub.c
    )
endif()


if ("${CONFIG_CRYPTO_ECC_WRAPPER}" STREQUAL "true" AND "${CONFIG_CRYPTO_SUPPORT_X509}" STREQUAL "true")
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/ec_wrapper_x509.c
    )
endif()

if ("${CONFIG_CRYPTO_ECC_WRAPPER}" STREQUAL "true")
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/ec_wrapper.c
    )
else()
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/stub/ec_wrapper_stub.c
        src/stub/ec_wrapper_x509_stub.c
    )
endif()

if ("${CONFIG_CRYPTO_AES_WRAPPER}" STREQUAL "true")
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/aes_wrapper.c
    )
else()
    set(SWCRYPTO_SRCS
        ${SWCRYPTO_SRCS}
        src/stub/aes_wrapper_stub.c
    )
endif()

list(APPEND TEE_C_DEFINITIONS OPENSSL_ENABLE)
list(APPEND SWCRYPTO_ENGINE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/openssl
    ${PREBUILD_DIR}/headers/openssl/openssl
    ${PREBUILD_DIR}/headers/openssl/crypto
)
set(SWCRYPTO_SRCS
    ${SWCRYPTO_SRCS}
    src/rsa_wrapper.c
)


list(APPEND SWCRYPTO_ENGINE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libcrypto_hal/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libtee_shared/include
    ${PROJECT_SOURCE_DIR}/vendor/common/include
    ${PREBUILD_HEADER}/inner_sdk/gpapi
    ${PREBUILD_HEADER}/inner_sdk/teeapi
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
)

set(SWCRYPTO_SRCS
    ${SWCRYPTO_SRCS}
    src/device_key_wrapper.c
    src/crl_api.c
)

tee_add_library(swcrypto_engine STATIC
    SOURCES
    ${SWCRYPTO_SRCS}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${SWCRYPTO_ENGINE_INCLUDE_PATH}
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
