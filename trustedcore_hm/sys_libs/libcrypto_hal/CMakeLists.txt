add_custom_target(libcrypto_hal_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${HDR_L_DIR}
    VERBATIM)

include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)
include(apps_feature_macro)

if ("${CONFIG_ASCEND_SEC_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS ASCEND_SEC_ENABLE)
endif()
if ("${CONFIG_TRNG_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS SEC_ENABLE)
endif()
if ("${CONFIG_DRV_SEC_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS SEC_ENABLE)
endif()
if ("${CONFIG_IPC_SEC_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS SEC_ENABLE)
endif()
if ("${CONFIG_KUNPENG_SEC_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS SEC_ENABLE)
endif()

if ("${CONFIG_CRYPTO_SUPPORT_DES}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_DES=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_EC25519}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_EC25519=1)
endif()

if ("${CONFIG_CRYPTO_SUPPORT_MD5}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_MD5=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_SHA1}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_SHA1=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_SHA224}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_SHA224=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_3DES}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_3DES=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_UNSAFE_RSA}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_UNSAFE_RSA=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_UNSAFE_ECDSA}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_UNSAFE_ECDSA=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_UNSAFE_ECDH}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_UNSAFE_ECDH=1)
endif()
if ("${CONFIG_CRYPTO_SUPPORT_UNSAFE_DH}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_SSL_SUPPORT_UNSAFE_DH=1)
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_C_DEFINITIONS MBEDTLS_ENABLE)
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/mbedtls
    )
else()
    list(APPEND TEE_C_DEFINITIONS OPENSSL_ENABLE)
    list(APPEND TEE_INCLUDE_PATH
        ${PREBUILD_DIR}/headers/openssl
        ${PREBUILD_DIR}/headers/openssl/openssl
        ${PREBUILD_DIR}/headers/openssl/crypto
    )
endif()

if ("${CONFIG_CIPHER_ENABLE}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS
        DX_ENABLE=1
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/src/cclib
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee/
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pal
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/host/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include
    )
endif()
list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/common/crypto
    ${PROJECT_SOURCE_DIR}/drivers/base_mgr/crypto_mgr/src/crypto_ioctl
    ${PROJECT_SOURCE_DIR}/drivers/include
    ${PROJECT_SOURCE_DIR}/sys_libs/libteeconfig/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/cdrmr
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/libseceng/include/common
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/pal
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/crypto_enhance/host/include/adapter
    ${PREBUILD_HEADER}/inner_sdk/gpapi
    ${PROJECT_SOURCE_DIR}/inner_sdk/teeapi/common
)

list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

set(CRYPTOHAL_SRCS
    ${CRYPTOHAL_SRCS}
    src/crypto_hal.c
    src/crypto_hal_rsa.c
    src/crypto_hal_ec.c
    src/crypto_hal_ae.c
    src/crypto_hal_hash.c
    src/crypto_hal_hmac.c
    src/crypto_hal_cipher.c
    src/crypto_hal_derive_key.c
    src/crypto_alg_config.c
)

if ("${CONFIG_CIPHER_ENABLE}" STREQUAL "true")
    set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/crypto_ext_api.c
        src/tee_chinadrm_gmssl_api.c
    )
else()
    set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/crypto_ext_api_stub.c
        src/tee_chinadrm_gmssl_api_stub.c
    )
endif()

if ("${CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT}" STREQUAL "true")
    list(APPEND TEE_C_DEFINITIONS CRYPTO_MGR_SERVER_ENABLE)
    set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/crypto_mgr_manager.c
    )
else ()
    set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/crypto_manager.c
    )
endif()

if ("${CONFIG_CRYPTO_SOFT_ENGINE}" STREQUAL "mbedtls")
    list(APPEND TEE_C_DEFINITIONS MBEDTLS_ENABLE)
    set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/mbedtls/soft_ae.c
        src/mbedtls/soft_ec_api.c
        src/mbedtls/soft_rsa_api.c
        src/mbedtls/soft_derive_key_api.c
        src/mbedtls/soft_cipher.c
        src/mbedtls/soft_common_api.c
        src/mbedtls/soft_hash.c
        src/mbedtls/soft_hmac.c
        src/mbedtls/soft_err.c
     )
else ()
     set(CRYPTOHAL_SRCS
        ${CRYPTOHAL_SRCS}
        src/boringssl/soft_ae.c
        src/boringssl/soft_ec_api.c
        src/boringssl/soft_rsa_api.c
        src/boringssl/soft_derive_key_api.c
        src/boringssl/soft_cipher.c
        src/boringssl/soft_common_api.c
        src/boringssl/soft_hash.c
        src/boringssl/soft_hmac.c
        src/boringssl/soft_err.c
        src/boringssl/soft_gmssl.c
        src/tee_chinadrm_gmssl_api.c
    )
endif()

tee_add_library(crypto_hal STATIC
    SOURCES
    ${CRYPTOHAL_SRCS}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
