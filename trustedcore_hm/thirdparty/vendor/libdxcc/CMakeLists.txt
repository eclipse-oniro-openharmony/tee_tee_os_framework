string(FIND ${PROJECT_SOURCE_DIR} "hm-teeos" IS_TEEOS)
if (IS_TEEOS GREATER 0)
    set(DXCC_DEST_FOLDER ${HMAPPSINCLUDE})
else()
    set(DXCC_DEST_FOLDER ${HDR_L_DIR})
endif()

if ("${CONFIG_CRYPTO_ENGINE_DX}" STREQUAL "y")
    file(GLOB COMMON_HOST_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/include/*.h)
    file(GLOB COMMON_CRYS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/crys/*.h)
    file(GLOB COMMON_DX_UTILS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/dx_util/*.h)
    file(GLOB COMMON_SHARED_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/pal/*.h)
    file(GLOB COMMON_CRYS_RSA_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rsa/crys_rsa/inc/*.h)
    file(GLOB COMMON_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/pal/include/*.h)
    add_custom_command(OUTPUT libdxcc_headers_common
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/cclib/dx_cclib.h ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_HOST_INCLUDES} ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_CRYS_INCLUDES} ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_DX_UTILS_INCLUDES} ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_SHARED_PAL_INCLUDES} ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_CRYS_RSA_INCLUDES} ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/sep_ctx.h ${DXCC_DEST_FOLDER}
        COMMAND ${CMAKE_COMMAND} -E copy ${COMMON_PAL_INCLUDES} ${DXCC_DEST_FOLDER}
    )
    list(APPEND LIBDXCC_COMMANG libdxcc_headers_common)
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "orlando" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "hi9500" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "hi9510" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "denver" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "burbank" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "lexington" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "laguna")
        file(GLOB PLAT_HOST_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/pal/*.h)
        file(GLOB PLAT_HMOS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/pal/hmos/*.h)
        file(GLOB PLAT_CRYPTO_API_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/crypto_api/*.h)
        file(GLOB PLAT_CC7X_TEE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/crypto_api/cc7x_tee/*.h)
        file(GLOB PLAT_PROJ_CC7X_TEE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/proj/cc7x_tee/*.h)
        file(GLOB PLAT_CC_UTIL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/cc_util/*.h)
        add_custom_command(OUTPUT libdxcc_headers_platform
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/host/src/cc7x_teelib/cc_lib.h ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HOST_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HMOS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYPTO_API_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CC7X_TEE_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_PROJ_CC7X_TEE_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CC_UTIL_INCLUDES} ${DXCC_DEST_FOLDER}
        )
        list(APPEND LIBDXCC_COMMANG libdxcc_headers_platform)
    endif()
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "mt6765" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6873" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6853" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6761" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6768" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6885")
        file(GLOB PLAT_SHARED_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/pal/*.h)
        file(GLOB PLAT_HMOS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/pal/hmos/*.h)
        file(GLOB PLAT_CRYS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/crys/*.h)
        file(GLOB PLAT_CRYS_CC710TEE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/crys/cc710tee/*.h)
        file(GLOB PLAT_PROJ_CC710TEE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/proj/cc710tee/*.h)
        file(GLOB PLAT_SSI_UTIL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/shared/include/ssi_util/*.h)
        add_custom_command(OUTPUT libdxcc_headers_platform
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/mtk/tzcc_fw/host/src/cc710teelib/sns_silib.h ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HMOS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYS_CC710TEE_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_PROJ_CC710TEE_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_SSI_UTIL_INCLUDES} ${DXCC_DEST_FOLDER}
        )
        list(APPEND LIBDXCC_COMMANG libdxcc_headers_platform)
    endif()
    if ("${TARGET_BOARD_PLATFORM}" STREQUAL "shaolingun" OR
        "${TARGET_BOARD_PLATFORM}" STREQUAL "hi3716mv430n")
        file(GLOB PLAT_SHARED_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/pal/*.h)
        file(GLOB PLAT_HMOS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/pal/hmos/*.h)
        file(GLOB PLAT_CRYPTO_API_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/crypto_api/*.h)
        file(GLOB PLAT_CRYPTO_API_CC7X_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/crypto_api/cc7x_tee/*.h)
        file(GLOB PLAT_PROJ_CC7X_TEE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/proj/cc7x_tee/*.h)
        file(GLOB PLAT_CC_UTIL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/shared/include/cc_util/*.h)
        file(GLOB PLAT_HOST_CCLIB_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/cclib/*.h)
        file(GLOB PLAT_HOST_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/include/*.h)
        file(GLOB PLAT_SHARED_CRYS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/crys/*.h)
        file(GLOB PLAT_SHARED_DX_UTILS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/dx_util/*.h)
        file(GLOB PLAT_AUSTIN_SHARED_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/pal/*.h)
        file(GLOB PLAT_CRYS_RSA_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rsa/crys_rsa/inc/*.h)
        file(GLOB PLAT_PAL_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/pal/include/*.h)
        add_custom_command(OUTPUT libdxcc_headers_platform
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/atlanta/host/src/cc7x_teelib/cc_lib.h ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_SHARED_PAL_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HMOS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYPTO_API_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYPTO_API_CC7X_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_PROJ_CC7X_TEE_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CC_UTIL_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HOST_CCLIB_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_HOST_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_SHARED_CRYS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_SHARED_DX_UTILS_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_AUSTIN_SHARED_PAL_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_CRYS_RSA_INCLUDES} ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/sep_ctx.h ${DXCC_DEST_FOLDER}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLAT_PAL_INCLUDES} ${DXCC_DEST_FOLDER}
        )
        list(APPEND LIBDXCC_COMMANG libdxcc_headers_platform)
    endif()
    add_custom_target(libdxcc_headers ALL DEPENDS ${LIBDXCC_COMMANG})
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/tools
    ${PREBUILD_HEADER}/boringssl
)

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin710" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "miamicw" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "qemu" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "hi6965" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "hi6932")
    include(apps_lib_common)
    include(apps_svc_common)
    include(apps_sub_cfg)
    include(apps_subcommon)
    list(REMOVE_ITEM TEE_C_FLAGS -nostdinc)

    list(APPEND TEE_C_FLAGS
        -DARM_CPU_CORTEX_A15=1
        -DDX_CONFIG_HASH_XOR_SUPPORTED
        -DDX_SOFT_KEYGEN
        -DDX_SOFT_KEYGEN_SIZE=3072
        -DDX_CRYS_KEYGEN_MAX_SIZE=
        -DCC_HW_VERSION=0xBF
        -DLITTLE__ENDIAN
        -DHASLONGLONG
        -D__arm64__
        -DDEBUG
        -DDX_CC_SRAM_INDIRECT_ACCESS
        -DTEE_DEBUG
        -DFW_VER_MAJOR=1
        -DFW_VER_MINOR=0
        -DFW_VER_PATCH=0
        -DDX_CC_TEE
        -DMAX_NUM_HW_QUEUES=1
        -DDLLI_MAX_BUFF_SIZE=128
        -DDX_SEC_TIMER_TEST_ENV
        -DFW_MLLI_TABLE_LEN=128
        -DSEP_SUPPORT_SHA=512
        -DMIN_CRYPTO_TAIL_SIZE=32
        -DDEBUG_OAEP_SEED=0
        -DCRYS_RSA_SIGN_USE_TEMP_SALT=0
        -DENABLE_AES_DRIVER=1
        -DENABLE_DES_DRIVER=1
        -DENABLE_HASH_DRIVER=1
        -DENABLE_HMAC_DRIVER=1
        -DENABLE_RC4_DRIVER=0
        -DENABLE_AEAD_DRIVER=1
        -DENABLE_ECC_DRIVER=1
        -DENABLE_RSA_DRIVER=1
        -DENABLE_BYPASS_DRIVER=1
        -DENABLE_COMBINED_DRIVER=0
        -DENABLE_KDF_DH_DRIVER=1
        -DENABLE_C2_DRIVER=0
        -DCRYS_NO_FIPS_SUPPORT
        -DCRYS_NO_RSA_SELF_TEST_SUPPORT
        -DCRYS_RND_SEM_DISABLE
        -DCRYS_PKA_INDIRECT_SRAM_ACCESS_MODE
        -DCRYS_NO_CRYS_COMBINED_SUPPORT
        -DDX_CONFIG_HASH_SHA_512_SUPPORTED
        -DSEP_CTX_SIZE_LOG2=8
        -DDX_CONFIG_HASH_MD5_SUPPORTED
        -DDX_DMA_48BIT_SIM=0
        -DDX_SB_ADDITIONAL_DATA_SUPPORTED
        -DCC_HW_VERSION=0xBF
        -DDX_SB_CERT_VERSION_MAJOR=1
        -DDX_SB_CERT_VERSION_MINOR=0
        -DSEP_SUPPORT_SHA=512
        -DDX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES=8192
    )

    list(APPEND TEE_INCLUDE_PATH
        ${CMAKE_CURRENT_SOURCE_DIR}/pal/include
        ${CMAKE_CURRENT_SOURCE_DIR}/pal/src
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/softcrys/pki
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rsa/ccsw_rsa
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/cclib/tee/public-rom/include
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/sym/driver
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/sym/api
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/driver
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/pal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/hal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/pal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/hw/include
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/crys
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/common/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/gen/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rsa/crys_rsa/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/kdf/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/dh/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/common/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/ccm/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/gen/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/gen/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/dx_util
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rsa/llf_pki/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/ecc/llf_pki_ec/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/rnd_dma
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/cclib
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/pal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/secure_boot_gen
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/crypto_driver
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/platform/nvm/nvm_mng
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/platform/hal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/platform/nvm
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/gen
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/util
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/boot_images_verifier
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/sw_revocation_manager
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/hw/include
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/cclib/tee
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/hal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/crys/sym/driver
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/sbrom
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/vrl_verifier
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/src/sb_runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/codesafe/src/runtime_secure_boot/platform/pal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/pal
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/shared/include/proj/cc63
        ${CMAKE_CURRENT_SOURCE_DIR}/austin/host/include
    )

    if ("${CONFIG_ARM32_FLUSH_CACHE}" STREQUAL "true")
        list(APPEND TEE_C_DEFINITIONS
            CONFIG_ARM32_FLUSH_CACHE
        )
    endif()

    list(APPEND TEE_C_SOURCES
        pal/src/bget.c
        pal/src/dx_pal.c
        pal/src/dx_pal_log.c
        pal/src/dx_pal_barrier.c
        pal/src/dx_pal_memmap.c
        pal/src/dx_pal_dma.c
        pal/src/dx_pal_mutex.c
        pal/src/dx_pal_hmsyscall.c
        austin/host/src/cclib/tee/bypass.c
        austin/host/src/cclib/tee/cc_acl_plat.c
        austin/host/src/cclib/tee/cc_plat.c
        austin/host/src/cclib/tee/completion_plat.c
        austin/host/src/cclib/tee/dma_buffer.c
        austin/host/src/cclib/tee/dx_cclib.c
        austin/host/src/cclib/tee/dx_rng_plat.c
        austin/host/src/cclib/tee/dx_util.c
        austin/host/src/cclib/tee/dx_util_oem_asset.c
        austin/host/src/cclib/tee/dx_util_rpmb_adaptor.c
        austin/host/src/cclib/tee/dx_util_rpmb.c
        austin/host/src/cclib/tee/dx_util_stimer.c
        austin/host/src/cclib/tee/hw_queue_plat.c
        austin/host/src/cclib/tee/key_buffer.c
        austin/host/src/cclib/tee/mlli_plat.c
        austin/host/src/cclib/tee/sbrt_management_api.c
        austin/host/src/cclib/tee/secure_key_gen.c
        austin/host/src/cclib/tee/sym_adaptor_driver.c
        austin/host/src/cclib/tee/validate_crys_bypass_plat.c
        austin/codesafe/src/crys/ccm/src/crys_ccm.c
        austin/codesafe/src/crys/common/src/crys_common_conv_endian.c
        austin/codesafe/src/crys/common/src/crys_common_math.c
        austin/codesafe/src/crys/dh/src/crys_dh.c
        austin/codesafe/src/crys/dh/src/crys_dh_kg.c
        austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/src/crys_ecpki_build.c
        austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/src/crys_ecpki_kg.c
        austin/codesafe/src/crys/ecc/crys_ecc/ecdh/src/crys_ecdh.c
        austin/codesafe/src/crys/ecc/crys_ecc/ecdsa/src/crys_ecdsa_sign.c
        austin/codesafe/src/crys/ecc/crys_ecc/ecdsa/src/crys_ecdsa_verify.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_domains.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_ec_arithmetic.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_ecdsa.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_export.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_genkey.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_modular_arithmetic.c
        austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_version.c
        austin/codesafe/src/crys/gen/src/dx_asym_init.c
        austin/codesafe/src/crys/kdf/src/crys_kdf.c
        austin/codesafe/src/crys/rnd_dma/crys_rnd.c
        austin/codesafe/src/crys/rnd_dma/llf_rnd.c
        austin/codesafe/src/crys/rsa/ccsw_rsa/ccsw_crys_rsa_kg.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_build.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_kg.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_oaep.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_pkcs_ver15_util.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_prim.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_pss21_util.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_sign.c
        austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_verify.c
        austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_exp.c
        austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_genkey.c
        austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_genkey_x931_find_prime.c
        austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_pka.c
        austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_rsa.c
        austin/codesafe/src/crys/sym/api/crys_aes.c
        austin/codesafe/src/crys/sym/api/crys_aesccm.c
        austin/codesafe/src/crys/sym/api/crys_bypass.c
        austin/codesafe/src/crys/sym/api/crys_des.c
        austin/codesafe/src/crys/sym/api/crys_hash.c
        austin/codesafe/src/crys/sym/api/crys_hmac.c
        austin/codesafe/src/crys/sym/driver/aead.c
        austin/codesafe/src/crys/sym/driver/cipher.c
        austin/codesafe/src/crys/sym/driver/hash.c
        austin/codesafe/src/crys/sym/driver/hmac.c
        austin/codesafe/src/crys/sym/driver/hw_queue.c
        austin/codesafe/src/crys/sym/driver/mlli.c
        austin/codesafe/src/crys/sym/driver/sym_crypto_driver.c
        austin/codesafe/src/runtime_secure_boot/crypto_driver/crypto_driver_adaptor.c
        austin/codesafe/src/runtime_secure_boot/crypto_driver/crypto_driver.c
        austin/codesafe/src/runtime_secure_boot/platform/nvm/nvm_mng/nvm_mng.c
        austin/codesafe/src/runtime_secure_boot/secure_boot_gen/secureboot_base_func.c
        austin/codesafe/src/runtime_secure_boot/util/util.c
        austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_base_single.c
        austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_parser.c
        austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_swcomp.c
        austin/host/src/cclib/crys_context_relocation.c
        austin/host/src/hal/dx_hal.c
        austin/host/src/softcrys/pki/llf_pki_util_div.c
        austin/host/src/softcrys/pki/llf_pki_util_exp.c
        austin/host/src/softcrys/pki/llf_pki_util_exp_crt.c
        austin/host/src/softcrys/pki/llf_pki_util_invmod.c
        austin/host/src/softcrys/pki/llf_pki_util_monmul_32x32.c
        austin/host/src/softcrys/pki/llf_pki_util_rmul.c
        austin/host/src/softcrys/pki/sw_llf_pki_genkey.c
        austin/host/src/softcrys/pki/sw_llf_pki_rsa.c
    )

    list(REMOVE_ITEM TEE_C_FLAGS "-Werror")
    tee_add_library(dx_cc7 STATIC
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

        NO_INSTALL
    )
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "kirin980" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "orlando" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "kirin990" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "hi9500" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "hi9510" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "denver" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "baltimore" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "lexington" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "burbank" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "laguna")
    add_subdirectory(atlanta)
endif()

if ("${TARGET_BOARD_PLATFORM}" STREQUAL "mt6765" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6873" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6853" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6761" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6768" OR
    "${TARGET_BOARD_PLATFORM}" STREQUAL "mt6885")
    add_subdirectory(mtk)
endif()
