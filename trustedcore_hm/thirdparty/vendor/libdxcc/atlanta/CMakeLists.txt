list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include(proj_cfg)
include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_HEADER}
    ${PREBUILD_HEADER}/boringssl
    ${PREBUILD_HEADER}/libc_32
    ${PREBUILD_HEADER}/libc_32/arch/${ARCH}
    ${PREBUILD_HEADER}/libc_32/arch/generic
    ${PREBUILD_HEADER}/gen/arch/${ARCH}
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/libthirdparty_drv/include
)
if ("${chip_type}" STREQUAL "cs2")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}_cs2
    )
else()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/../../../../hisi/ap/platform/${TARGET_BOARD_PLATFORM}
    )
endif()

list(APPEND CC_C_FLAGS
    -DLITTLE__ENDIAN
    -DHASLONGLONG
    -fno-omit-frame-pointer
)

list(APPEND CC_C_FLAGS
    -Wall
    -Wsign-compare
    -Wextra
    -Wpointer-arith
    -Wcast-align
    -Wstrict-prototypes
    -Wwrite-strings
    -Wswitch-default
    -Wunreachable-code
    -Winit-self
    -Wjump-misses-init
    -Wlogical-op
    -Wmissing-field-initializers
    -fno-stack-protector
)

list(APPEND CC_C_FLAGS
    -DWITH_CHIP_HI3680=${WITH_CHIP_HI3680}
    -DWITH_CHIP_KIRIN990=${WITH_CHIP_KIRIN990}
    -DWITH_CHIP_ORLANDO=${WITH_CHIP_ORLANDO}
    -DWITH_CHIP_BALTIMORE=${WITH_CHIP_BALTIMORE}
    -DWITH_CHIP_BURBANK=${WITH_CHIP_BURNANK}
    -DWITH_CHIP_LEXINGTON=${WITH_CHIP_LEXINGTON}
    -DWITH_CHIP_DENVER=${WITH_CHIP_DENVER}
    -DWITH_CHIP_MIAMICW=${WITH_CHIP_MIAMICW}
    -DWITH_CHIP_LAGUNA=${WITH_CHIP_LAGUNA}
    -DWITH_CHIP_HI9500=${WITH_CHIP_HI9500}
    -DWITH_CHIP_HI9510=${WITH_CHIP_HI9510}
    -DWITH_CHIP_HI6932=${WITH_CHIP_HI6932}
    -DWITH_CHIP_HI6965=${WITH_CHIP_HI6965}
    -DTRUSTEDCORE_CHIP_CHOOSE=${TRUSTEDCORE_CHIP_CHOOSE}
)
if ("${ARCH}" STREQUAL "arm")
    list(APPEND CC_C_FLAGS
        -D__arm__
    )
else()
    list(APPEND CC_C_FLAGS
        -D__arm64__
    )
endif()

list(APPEND CC_C_FLAGS
    -DCC_KEYGEN_MAX_SIZE=${CC_RSA_MAX_KEY_GENERATION_SIZE_BITS}
    -DCC_HW_VERSION=${CC_HW_VERSION}
)

if ("${DEBUG}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        host/src/pal/hmos/cc_pal_log.c
    )
endif()
if ("${PKA_DEBUG}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DPKA_DEBUG
    )
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/pki/common/pki_dbg.c
    )
endif()
list(APPEND CC_C_SOURCES
    host/src/pal/hmos/bget.c
    host/src/cc7x_teelib/cc_util_hw_key.c
    host/src/cc7x_teelib/cc_lib.c
    host/src/hal/cc7x_tee/cc_hal.c
    host/src/cc7x_teelib/completion_plat.c
    host/src/cc7x_teelib/hw_queue_plat.c
    host/src/pal/hmos/cc_pal.c
    host/src/pal/hmos/cc_pal_dma.c
    host/src/pal/hmos/cc_pal_memmap.c
    host/src/cc7x_teelib/mlli_plat.c
    host/src/cc7x_teelib/cc_context_relocation.c
    host/src/pal/hmos/cc_pal_mutex.c
    host/src/pal/hmos/cc_pal_barrier.c
    host/src/cc7x_teelib/cc_util_pm.c
    codesafe/src/crypto_api/cc7x_sym/api/cc_aes.c
    codesafe/src/crypto_api/cc7x_sym/api/cc_hash.c
    codesafe/src/crypto_api/cc7x_sym/api/cc_hmac.c
    codesafe/src/crypto_api/cc7x_sym/api/cc_des.c
    codesafe/src/crypto_api/cc7x_sym/api/cc_aesccm.c
    host/src/cc7x_teelib/sym_adaptor_driver.c
    codesafe/src/crypto_api/cc7x_sym/driver/hw_queue.c
    host/src/cc7x_teelib/cc_plat.c
    host/src/cc7x_teelib/bypass.c
    codesafe/src/crypto_api/cc7x_sym/driver/cipher.c
    codesafe/src/crypto_api/cc7x_sym/driver/hash.c
    codesafe/src/crypto_api/cc7x_sym/driver/hmac.c
    codesafe/src/crypto_api/cc7x_sym/driver/aead.c
    codesafe/src/crypto_api/cc7x_sym/driver/mlli.c
    codesafe/src/crypto_api/cc7x_sym/driver/sym_crypto_driver.c
    host/src/cc7x_teelib/cc_util_cmac.c
    host/src/cc7x_teelib/cc_util.c
    host/src/utils/cc_util_key_derivation.c
    host/src/utils/cc_util_oem_asset.c
    host/src/cc7x_teelib/cc_util_stimer.c
    host/src/cc7x_teelib/cc_util_rpmb.c
    host/src/cc7x_teelib/cc_util_rpmb_adaptor.c
    host/src/cc7x_teelib/cc_util_backup_restore.c
    codesafe/src/crypto_api/common/cc_common_math.c
    codesafe/src/crypto_api/common/cc_common_conv_endian.c
    shared/src/proj/cc7x_tee/cc_rsa_info.c
    codesafe/src/crypto_api/rsa/cc_rsa_build.c
    codesafe/src/crypto_api/rsa/cc_rsa_oaep.c
    codesafe/src/crypto_api/rsa/cc_rsa_schemes.c
    codesafe/src/crypto_api/rsa/cc_rsa_schemes_priv_enc.c
    codesafe/src/crypto_api/rsa/cc_rsa_pkcs_ver15_util.c
    codesafe/src/crypto_api/rsa/cc_rsa_pss21_util.c
    codesafe/src/crypto_api/rsa/cc_rsa_prim.c
    codesafe/src/crypto_api/rsa/cc_rsa_verify.c
    codesafe/src/crypto_api/rsa/cc_rsa_kg.c
    codesafe/src/crypto_api/rsa/cc_rsa_sign.c
    codesafe/src/crypto_api/dh/cc_dh.c
    codesafe/src/crypto_api/dh/cc_dh_kg.c
    codesafe/src/crypto_api/kdf/cc_kdf.c
    codesafe/src/crypto_api/rsa/cc_rsa_build_priv.c
    shared/src/proj/cc7x_tee/cc_ecpki_info.c
    codesafe/src/crypto_api/ec_wrst/cc_ecpki_build_publ.c
    codesafe/src/crypto_api/ec_wrst/cc_ecpki_build_priv.c
    codesafe/src/crypto_api/ec_wrst/cc_ecdsa_verify.c
    codesafe/src/crypto_api/ec_wrst/cc_ecdsa_sign.c
    codesafe/src/crypto_api/ec_wrst/cc_ecpki_kg.c
    codesafe/src/crypto_api/ec_wrst/cc_ecdh.c
    codesafe/src/crypto_api/pki/ec_wrst/ec_wrst_genkey.c
    codesafe/src/crypto_api/ec_wrst/cc_ecies.c
    codesafe/src/crypto_api/rnd_dma/cc_rnd.c
    codesafe/src/crypto_api/rnd_dma/llf_rnd.c
    host/src/cc7x_teelib/cc_rng_plat.c
    codesafe/src/crypto_api/pki/common/pka.c
    codesafe/src/crypto_api/pki/common/pki_modular_arithmetic.c
    codesafe/src/crypto_api/pki/rsa/rsa_public.c
    codesafe/src/crypto_api/pki/rsa/rsa_private.c
    codesafe/src/crypto_api/pki/common/pki.c
    codesafe/src/crypto_api/pki/rsa/rsa_genkey.c
    codesafe/src/crypto_api/pki/ec_wrst/pka_ec_wrst.c
    codesafe/src/crypto_api/pki/ec_wrst/pka_ec_wrst_dsa_verify.c
    codesafe/src/crypto_api/pki/ec_wrst/ec_wrst.c
    codesafe/src/crypto_api/pki/ec_wrst/ec_wrst_dsa.c
    codesafe/src/crypto_api/ec_wrst/cc_ecpki_domain.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp160k1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp160r1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp160r2.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp192r1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp192k1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp224r1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp224k1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp256r1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp256k1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp384r1.c
    codesafe/src/crypto_api/ec_wrst/ecc_domains/cc_ecpki_domain_secp521r1.c
)

if ("${CC_CONFIG_TRNG_MODE}" STREQUAL "0")
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/rnd_dma/llf_rnd_fetrng.c
    )
    list(APPEND CC_C_FLAGS
        -DCC_CONFIG_TRNG_MODE=${CC_CONFIG_TRNG_MODE}
    )
elseif ("${CC_CONFIG_TRNG_MODE}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/rnd_dma/llf_rnd_trng90b.c
    )
    list(APPEND CC_C_FLAGS
        -DCC_CONFIG_TRNG_MODE=${CC_CONFIG_TRNG_MODE}
    )
elseif ("${CC_CONFIG_TRNG_MODE}" STREQUAL "2")
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/rnd_dma/llf_rnd_sweetrng.c
    )
    list(APPEND CC_C_FLAGS
        -DCC_CONFIG_TRNG_MODE=${CC_CONFIG_TRNG_MODE}
    )
else()
    message(FATAL_ERROR "illegal TRNG: CC_CONFIG_TRNG_MODE=${CC_CONFIG_TRNG_MODE}")
endif()

if ("${CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/pki/ec_wrst/pka_ec_wrst_smul_scap.c
    )
else()
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/pki/ec_wrst/pka_ec_wrst_smul_no_scap.c
    )
endif()

if ("${CC_CONFIG_SUPPORT_FIPS}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        codesafe/src/crypto_api/fips/cc_fips.c
        codesafe/src/crypto_api/fips/cc_fips_local.c
        codesafe/src/crypto_api/fips/cc_fips_sym.c
        host/src/pal/hmos/cc_pal_fips.c
        codesafe/src/crypto_api/fips/cc_fips_ecc.c
        codesafe/src/crypto_api/fips/cc_fips_rsa.c
        codesafe/src/crypto_api/fips/cc_fips_dh.c
        codesafe/src/crypto_api/fips/cc_fips_prng.c
    )
    list(APPEND CC_C_FLAGS
        -DCC_SUPPORT_FIPS
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/cc7x_teelib/cc_util_hw_key.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/cc7x_teelib/cc_lib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/cc_util/cc_util_key_derivation.h
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/cc7x_sym/driver
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/cc7x_sym/api
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/driver
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/pal
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/pal/hmos
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/hal
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/pal
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/pal/hmos
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/trng
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/hw/tee_include
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/crypto_api
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/common
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/gen
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/rsa
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/ec_wrst
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/ec_wrst/ecc_domains
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/gen
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/cc_util
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/pki/rsa
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/pki/ec_wrst
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/pki/common
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/rnd_dma
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/rnd_dma/local
    ${CMAKE_CURRENT_SOURCE_DIR}/host/src/cc7x_teelib
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include/proj/cc7x_tee
    ${CMAKE_CURRENT_SOURCE_DIR}/codesafe/src/crypto_api/fips
)

list(APPEND CC_C_FLAGS
    -DCC_SUPPORT_PKA_128_32
)

if ("${CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT}" STREQUAL 1)
    list(APPEND CC_C_FLAGS
        -DCC_SUPPORT_ECC_SCA_SW_PROTECT
    )
endif()

list(APPEND CC_C_FLAGS
    -DFW_VER_MAJOR=${FW_VER_MAJOR}
    -DFW_VER_MINOR=${FW_VER_MINOR}
    -DFW_VER_PATCH=${FW_VER_PATCH}
    -DCC_TEE
    -DDLLI_MAX_BUFF_SIZE=${DLLI_MAX_BUFF_SIZE}
    -DDX_SEC_TIMER_TEST_ENV
    -DFW_MLLI_TABLE_LEN=${FW_MLLI_TABLE_LEN}
    -DCC_SUPPORT_SHA=512
    -DMIN_CRYPTO_TAIL_SIZE=${MIN_CRYPTO_TAIL_SIZE}
)

if ("${CC_CONFIG_HASH_SHA_512_SUPPORTED}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DCC_CONFIG_HASH_SHA_512_SUPPORTED
        -DCC_CTX_SIZE_LOG2=8
    )
endif()

if ("${CC_CONFIG_HASH_MD5_SUPPORTED}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DCC_CONFIG_HASH_MD5_SUPPORTED
    )
endif()

if ("${CC_CONFIG_TEST_48BIT_DMA_ADDR}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DCC_DMA_48BIT_SIM
    )
endif()

if ("${CC_CONFIG_RND_TEST_MODE}" STREQUAL "CC_RND_TEST_MODE")
    list(APPEND CC_C_FLAGS
       -DCC_RND_TEST_MODE
    )
endif()

if ("${FW_ENABLE_AES_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_AES_DRIVER=${FW_ENABLE_AES_DRIVER}
    )
endif()

if ("${FW_ENABLE_DES_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_DES_DRIVER=${FW_ENABLE_DES_DRIVER}
    )
endif()

if ("${FW_ENABLE_HASH_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_HASH_DRIVER=${FW_ENABLE_HASH_DRIVER}
    )
endif()

if ("${FW_ENABLE_HMAC_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_HMAC_DRIVER=${FW_ENABLE_HMAC_DRIVER}
    )
endif()

if ("${FW_ENABLE_AEAD_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_AEAD_DRIVER=${FW_ENABLE_AEAD_DRIVER}
    )
endif()

if ("${FW_ENABLE_ECC_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_ECC_DRIVER=${FW_ENABLE_ECC_DRIVER}
    )
endif()

if ("${FW_ENABLE_RSA_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_RSA_DRIVER=${FW_ENABLE_RSA_DRIVER}
    )
endif()

if ("${FW_ENABLE_BYPASS_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_BYPASS_DRIVER=${FW_ENABLE_BYPASS_DRIVER}
    )
endif()

if ("${FW_ENABLE_KDF_DH_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_KDF_DH_DRIVER=${FW_ENABLE_KDF_DH_DRIVER}
    )
endif()

if ("${FW_ENABLE_C2_DRIVER}")
    list(APPEND CC_C_FLAGS
        -DENABLE_C2_DRIVER=${FW_ENABLE_C2_DRIVER}
    )
endif()

list(APPEND CC_C_FLAGS
    -DCC_SRAM_INDIRECT_ACCESS
)

list(REMOVE_ITEM TEE_C_FLAGS -DDEBUG)
list(REMOVE_ITEM TEE_C_FLAGS "-Werror")

tee_add_library(dx_cc7 STATIC
    SOURCES
    ${CC_C_SOURCES}

    COMPILE_TOOL
    clang

    COMPILER_FLAGS
    ${CC_C_FLAGS}
    ${TEE_C_FLAGS}

    COMPILER_DEFINITIONS
    ${TEE_C_DEFINITIONS}

    PRIVATE_INCLUDES
    ${TEE_INCLUDE_PATH}

    NO_INSTALL
)
