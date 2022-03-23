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
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_X509)
endif()

if ("${CONFIG_CRYPTO_ECC_WRAPPER}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SUPPORT_ECC_WRAPPER)
endif()

if ("${CONFIG_CRYPTO_AES_WRAPPER}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SUPPORT_AES_WRAPPER)
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_C_DEFINITIONS MBEDTLS_ENABLE)
    list(APPEND SWCRYPTO_ENGINE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/mbedtls
    )
elseif ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "boringssl")
    list(APPEND TEE_C_DEFINITIONS BORINGSSL_ENABLE)
else()
    list(APPEND TEE_C_DEFINITIONS OPENSSL_ENABLE)
    list(APPEND SWCRYPTO_ENGINE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/openssl
        ${PREBUILD_DIR}/headers/openssl/openssl
        ${PREBUILD_DIR}/headers/openssl/crypto
    )
endif()


list(APPEND SWCRYPTO_ENGINE_INCLUDE_PATH
    ${PREBUILD_DIR}/headers/boringssl
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
    src/x509_wrapper.c
    src/device_key_wrapper.c
    src/aes_wrapper.c
    src/create_cert_wrapper.c
    src/crl_api.c
    src/ec_wrapper.c
    src/tee_ext_cert_api.c
    src/rsa_wrapper.c
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
