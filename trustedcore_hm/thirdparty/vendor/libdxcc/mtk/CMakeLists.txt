list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include(proj_cfg)
include(apps_lib_common)
include(apps_svc_common)
include(apps_sub_cfg)
include(apps_subcommon)

list(APPEND TEE_INCLUDE_PATH
    ${PREBUILD_HEADER}
    ${PREBUILD_HEADER}/boringssl
    ${PREBUILD_HEADER}/kernel/uapi
    ${PREBUILD_HEADER}/kernel
    ${PREBUILD_HEADER}/kernel/arch/arm/uapi
    ${PREBUILD_HEADER}/hm_32
    ${PREBUILD_HEADER}/libc_32
    ${PREBUILD_HEADER}/libc_32/arch/${ARCH}
    ${PREBUILD_HEADER}/libc_32/arch/generic
    ${PREBUILD_HEADER}/gen/arch/${ARCH}
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/include
)

if ("${DEBUG}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        tzcc_fw/host/src/pal/hmos/ssi_pal_log.c
    )
endif()

if ("${PKA_DEBUG}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/pki/pka/pka_dbg.c
    )
    list(APPEND CC_C_FLAGS
        -DPKA_DEBUG
    )
endif()

list(APPEND CC_C_SOURCES
    tzcc_fw/host/src/pal/hmos/bget.c
)

list(APPEND CC_C_FLAGS
    -DDX_SaSi_KEYGEN_MAX_SIZE=${SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS}
    -DCC_HW_VERSION=${CC_HW_VERSION}
)

list(APPEND CC_C_SOURCES
    tzcc_fw/host/src/cc710teelib/sns_silib.c
    tzcc_fw/host/src/hal/cc710tee/ssi_hal.c
    tzcc_fw/host/src/cc710teelib/completion_plat.c
    tzcc_fw/host/src/cc710teelib/hw_queue_plat.c
    tzcc_fw/host/src/cc710teelib/dma_buffer.c
    tzcc_fw/host/src/pal/hmos/ssi_pal.c
    tzcc_fw/host/src/pal/hmos/ssi_pal_dma.c
    tzcc_fw/host/src/pal/hmos/ssi_pal_memmap.c
    tzcc_fw/host/src/cc710teelib/mlli_plat.c
    tzcc_fw/host/src/cc710teelib/sasi_context_relocation.c
    tzcc_fw/host/src/pal/hmos/ssi_pal_mutex.c
    tzcc_fw/host/src/pal/hmos/ssi_pal_barrier.c
    tzcc_fw/codesafe/src/crys/sym/api/ssi_aes.c
    tzcc_fw/codesafe/src/crys/sym/api/sasi_hash.c
    tzcc_fw/codesafe/src/crys/sym/api/sasi_hmac.c
    tzcc_fw/codesafe/src/crys/sym/api/sasi_des.c
    tzcc_fw/codesafe/src/crys/sym/api/sasi_aesccm.c
    tzcc_fw/host/src/cc710teelib/sym_adaptor_driver.c
    tzcc_fw/codesafe/src/crys/sym/driver/hw_queue.c
    tzcc_fw/host/src/cc710teelib/cc_plat.c
    tzcc_fw/host/src/cc710teelib/bypass.c
    tzcc_fw/codesafe/src/crys/sym/driver/cipher.c
    tzcc_fw/codesafe/src/crys/sym/driver/hash.c
    tzcc_fw/codesafe/src/crys/sym/driver/hmac.c
    tzcc_fw/codesafe/src/crys/sym/driver/aead.c
    tzcc_fw/codesafe/src/crys/sym/driver/mlli.c
    tzcc_fw/codesafe/src/crys/sym/driver/sym_crypto_driver.c
    tzcc_fw/host/src/cc710teelib/ssi_util_cmac.c
    tzcc_fw/host/src/cc710teelib/ssi_util.c
    tzcc_fw/host/src/utils/ssi_util_key_derivation.c
    tzcc_fw/host/src/utils/ssi_util_oem_asset.c
    tzcc_fw/host/src/cc710teelib/ssi_util_stimer.c
    tzcc_fw/host/src/cc710teelib/ssi_util_rpmb.c
    tzcc_fw/host/src/cc710teelib/ssi_util_rpmb_adaptor.c
    tzcc_fw/host/src/cc710teelib/ssi_util_backup_restore.c
    tzcc_fw/host/src/cc710teelib/ssi_util_ccm.c
    tzcc_fw/codesafe/src/crys/common/sasi_common_math.c
    tzcc_fw/codesafe/src/crys/common/sasi_common_conv_endian.c
    tzcc_fw/shared/src/proj/cc710tee/ssi_rsa_info.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_build.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_oaep.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_schemes.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_pkcs_ver15_util.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_pss21_util.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_prim.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_verify.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_kg.c
    tzcc_fw/codesafe/src/crys/rsa/sasi_rsa_sign.c
    tzcc_fw/codesafe/src/crys/dh/sasi_dh.c
    tzcc_fw/codesafe/src/crys/dh/sasi_dh_kg.c
    tzcc_fw/codesafe/src/crys/kdf/sasi_kdf.c
    tzcc_fw/shared/src/proj/cc710tee/ssi_ecpki_info.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecpki_build_publ.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecpki_build_priv.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecdsa_verify.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecdsa_sign.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecpki_kg.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecdh.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecies.c
    tzcc_fw/codesafe/src/crys/pki/ecc/llf_ecpki_genkey.c
    tzcc_fw/codesafe/src/crys/rnd_dma/sasi_rnd.c
    tzcc_fw/codesafe/src/crys/rnd_dma/llf_rnd.c
    tzcc_fw/host/src/cc710teelib/ssi_rng_plat.c
)

if ("${SSI_CONFIG_TRNG_MODE}" STREQUAL "0")
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/rnd_dma/llf_rnd_fetrng.c
    )
    list(APPEND CC_C_FLAGS
        -DSSI_CONFIG_TRNG_MODE=${SSI_CONFIG_TRNG_MODE}
    )
elseif ("${SSI_CONFIG_TRNG_MODE}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/rnd_dma/llf_rnd_trng90b.c
    )
    list(APPEND CC_C_FLAGS
        -DSSI_CONFIG_TRNG_MODE=${SSI_CONFIG_TRNG_MODE}
    )
elseif ("${SSI_CONFIG_TRNG_MODE}" STREQUAL "2")
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/rnd_dma/llf_rnd_sweetrng.c
        tzcc_fw/codesafe/src/crys/rnd_dma/mtk_trng_dx.c
    )
    list(APPEND CC_C_FLAGS
        -DSSI_CONFIG_TRNG_MODE=${SSI_CONFIG_TRNG_MODE}
    )
else()
    message(FATAL_ERROR "illegal TRNG: SSI_CONFIG_TRNG_MODE=${SSI_CONFIG_TRNG_MODE}")
endif()

list(APPEND CC_C_SOURCES
    tzcc_fw/codesafe/src/crys/pki/pka/pka.c
    tzcc_fw/codesafe/src/crys/pki/pka/pka_modular_arithmetic.c
    tzcc_fw/codesafe/src/crys/pki/rsa/llf_rsa_public.c
    tzcc_fw/codesafe/src/crys/pki/rsa/llf_rsa_private.c
    tzcc_fw/codesafe/src/crys/pki/pka/llf_pka.c
    tzcc_fw/codesafe/src/crys/pki/rsa/llf_rsa_genkey.c
    tzcc_fw/codesafe/src/crys/pki/ecc/pka_ecc.c
    tzcc_fw/codesafe/src/crys/pki/ecc/pka_ecc_point.c
    tzcc_fw/codesafe/src/crys/pki/ecc/pka_ecdsa_verify.c
    tzcc_fw/codesafe/src/crys/pki/ecc/llf_ecc.c
    tzcc_fw/codesafe/src/crys/pki/ecc/llf_ecdsa_verify.c
    tzcc_fw/codesafe/src/crys/ecc/sasi_ecpki_domain.c
    tzcc_fw/codesafe/src/crys/pki/ecc/llf_ecdsa_sign.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp160k1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp160r1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp160r2.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp192r1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp192k1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp224r1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp224k1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp256r1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp256k1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp384r1.c
    tzcc_fw/codesafe/src/crys/ecc/ecc_domains/ssi_ecpki_domain_secp521r1.c
)

if ("${DX_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT}" STREQUAL "1")
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/pki/ecc/pka_ecc_scalar_mult_scap.c
    )
else()
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/pki/ecc/pka_ecc_scalar_mult_no_scap.c
    )
endif()

if ("${DX_CONFIG_SUPPORT_FIPS}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DSSI_SUPPORT_FIPS
    )
    list(APPEND CC_C_SOURCES
        tzcc_fw/codesafe/src/crys/fips/sasi_fips.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_local.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_sym.c
        tzcc_fw/codesafe/src/crys/fips/ssi_pal_fips.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_ecc.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_rsa.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_dh.c
        tzcc_fw/codesafe/src/crys/fips/sasi_fips_prng.c
    )
endif()

list(APPEND CC_C_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SHARED_INCDIR}/crys/${PROJ_PRD}
)

if ("${DX_CONFIG_SECURE_KEY_PACKAGE_SUPPORTED}" STREQUAL "1")
    list(APPEND CC_C_INCLUDES
        ${ROM_RELEASE_DIR}/include
    )
    list(APPEND CC_C_SOURCES
        tzcc_fw/host/src/cc710teelib/secure_key_gen.c
    )
endif()

list(APPEND CC_C_INCLUDES
    ${CODESAFE_SRCDIR}/crys/sym/driver
    ${CODESAFE_SRCDIR}/crys/sym/api
    ${CODESAFE_SRCDIR}/crys/driver
    ${SHARED_INCDIR}
    ${SHARED_INCDIR}/pal
    ${SHARED_INCDIR}/pal/${OS}
    ${HOST_SRCDIR}/hal
    ${HOST_SRCDIR}/pal
    ${HOST_SRCDIR}/pal/${OS}
    ${SHARED_INCDIR}/trng
    ${SHARED_DIR}/hw/include
    ${SHARED_INCDIR}/crys
    ${CODESAFE_SRCDIR}/crys/common
    ${CODESAFE_SRCDIR}/crys/gen
    ${CODESAFE_SRCDIR}/crys/rsa
    ${CODESAFE_SRCDIR}/crys/ecc
    ${CODESAFE_SRCDIR}/crys/ecc/ecc_domains
    ${CODESAFE_SRCDIR}/crys/gen
    ${SHARED_INCDIR}/ssi_util
    ${CODESAFE_SRCDIR}/crys/pki/rsa
    ${CODESAFE_SRCDIR}/crys/pki/ecc
    ${CODESAFE_SRCDIR}/crys/pki/pka
    ${CODESAFE_SRCDIR}/crys/rnd_dma
    ${CODESAFE_SRCDIR}/crys/rnd_dma/local
    ${HOST_LIBDIR}
    ${SHARED_INCDIR}/proj/${PROJ_DIR}
    ${CODESAFE_SRCDIR}/crys/fips
    ${SHARED_INCDIR}
    $(SHARED_INCDIR)/proj/$(PROJ_DIR)
    $(HOST_PROJ_ROOT)/include
)

list(APPEND CC_C_FLAGS
    -DSSI_SUPPORT_PKA_128_32
)

if ("${DX_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DSSI_SUPPORT_ECC_SCA_SW_PROTECT
    )
endif()

list(APPEND CC_C_FLAGS
    -DFW_VER_MAJOR=${FW_VER_MAJOR}
    -DFW_VER_MINOR=${FW_VER_MINOR}
    -DFW_VER_PATCH=${FW_VER_PATCH}
    -DDX_CC_TEE
    -DMAX_NUM_HW_QUEUES=${FW_MAX_NUM_HW_QUEUES}
    -DDLLI_MAX_BUFF_SIZE=${DLLI_MAX_BUFF_SIZE}
    -DDX_SEC_TIMER_TEST_ENV
    -DFW_MLLI_TABLE_LEN=${FW_MLLI_TABLE_LEN}
    -DSEP_SUPPORT_SHA=512
    -DMIN_CRYPTO_TAIL_SIZE=${MIN_CRYPTO_TAIL_SIZE}
)

if ("${FW_ENABLE_AES_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_AES_DRIVER=${FW_ENABLE_AES_DRIVER}
    )
endif()
if ("${FW_ENABLE_DES_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_DES_DRIVER=${FW_ENABLE_DES_DRIVER}
    )
endif()
if ("${FW_ENABLE_HASH_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_HASH_DRIVER=${FW_ENABLE_HASH_DRIVER}
    )
endif()
if ("${FW_ENABLE_HMAC_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_HMAC_DRIVER=${FW_ENABLE_HMAC_DRIVER}
    )
endif()
if ("${FW_ENABLE_AEAD_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_AEAD_DRIVER=${FW_ENABLE_AEAD_DRIVER}
    )
endif()
if ("${FW_ENABLE_ECC_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_ECC_DRIVER=${FW_ENABLE_ECC_DRIVER}
    )
endif()
if ("${FW_ENABLE_RSA_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_RSA_DRIVER=${FW_ENABLE_RSA_DRIVER}
    )
endif()
if ("${FW_ENABLE_BYPASS_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_BYPASS_DRIVER=${FW_ENABLE_BYPASS_DRIVER}
    )
endif()
if ("${FW_ENABLE_KDF_DH_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_KDF_DH_DRIVER=${FW_ENABLE_KDF_DH_DRIVER}
    )
endif()
if ("${FW_ENABLE_C2_DRIVER}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DENABLE_C2_DRIVER=${FW_ENABLE_C2_DRIVER}
    )
endif()

list(APPEND CC_C_FLAGS
    -DSaSi_RND_SEM_DISABLE
    -DSaSi_PKA_INDIRECT_SRAM_ACCESS_MODE
    -DSaSi_NO_SaSi_COMBINED_SUPPORT
)

if ("${DX_CONFIG_HASH_MD5_SUPPORTED}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DDX_CONFIG_HASH_MD5_SUPPORTED
    )
endif()
if ("${DX_CONFIG_RSA_PRIV_KEY_CRT_SUPPORTED}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DDX_CONFIG_RSA_PRIV_KEY_CRT_SUPPORTED
    )
endif()
if ("${DX_CONFIG_TEST_48BIT_DMA_ADDR}" STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -DDX_DMA_48BIT_SIM
    )
endif()
if ("${DX_CONFIG_RND_TEST_MODE}" STREQUAL "DX_RND_TEST_MODE")
    list(APPEND CC_C_FLAGS
        -DDX_RND_TEST_MODE
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
    -DWITH_CHIP_MT6765=${WITH_CHIP_MT6765}
    -DWITH_CHIP_MT6873=${WITH_CHIP_MT6873}
    -DWITH_CHIP_MT6853=${WITH_CHIP_MT6853}
    -DWITH_CHIP_MT6768=${WITH_CHIP_MT6768}
    -DWITH_CHIP_MT6885=${WITH_CHIP_MT6885}
    -DTRUSTEDCORE_CHIP_CHOOSE=${TRUSTEDCORE_CHIP_CHOOSE}
)

if ("${TRUSTEDCORE_CHIP_CHOOSE}" STREQUAL "WITH_CHIP_MT6885")
    set(SSI_CONFIG_TRNG_MODE 2)
endif()

if (${DEBUG} STREQUAL "1")
    list(APPEND CC_C_FLAGS
        -O0 -DDEBUG
    )
    if (NOT "${ARCH}" STREQUAL "arm")
        list(APPEND CC_C_FLAGS
            -g3
        )
    endif()
else()
    list(APPEND CC_C_FLAGS
        -O2
    )
endif()

list(REMOVE_ITEM TEE_C_FLAGS -DDEBUG)
list(REMOVE_ITEM TEE_C_FLAGS -nostdinc)
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
    ${CC_C_INCLUDES}

    NO_INSTALL
)
