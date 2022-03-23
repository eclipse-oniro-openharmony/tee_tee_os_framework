set(TZASC_VERSION v400)

list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/os_hal/itrustee/module_mgr.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/os_hal/itrustee/tee_drv_os_hal.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/hi_tee_drv_tzasc.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/tee_drv_tzasc_common.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/hal/${TZASC_VERSION}/tee_drv_tzasc_${TZASC_VERSION}.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem_layout/tee_drv_mem_layout.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/init.c
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/license/hi_license.c
)

if ("${CFG_HI_TEE_SEC_MMZ_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/media_mem.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/mmz_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/mmz_ext.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/mmz_user.c
    )
endif()
if ("${CFG_HI_TEE_SMMU_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/hi_smmu_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/bitmap.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/hi_smmu.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/hi_smmu_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/hi_smmu_mem.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/hi_smmu_test.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/hi_smmu/include
    )
endif()

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/hal/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/hal/${TZASC_VERSION}
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem_layout/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/os_hal/itrustee
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tzasc/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/include
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem_layout
)

if ("${CFG_HI_TEE_DEBUG_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS -DTEE_DRV_TZASC_DEBUGT)
    list(APPEND TEE_C_FLAGS -DTEE_DRV_MEM_LAYOUT_DEBUG)
endif()

list(APPEND TEE_C_FLAGS
    -DDX_ENABLE=1
)


if ("${CFG_HI_TEE_LOG_SUPPORT}" STREQUAL "y")
list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/common/log/tee_drv_log.c
)
endif()

if ("${CFG_HI_TEE_CIPHER_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS
        -DHI_SHA1_DISABLE
        -DHI_SHA224_DISABLE
        -DHI_PLATFORM_TYPE_LINUX
        -DHI_PRODUCT_SHA512_SUPPORT
        -DHI_PRODUCT_DMA_SUPPORT
        -DHI_PRODUCT_ODD_KEY_SUPPORT
        -DHI_PRODUCT_MULTI_CIPHER_SUPPORT
        -DHI_PRODUCT_SYMC_CONFIG_EX_SUPPORT
        -DHI_PRODUCT_AEAD_SUPPORT
        -DHI_PRODUCT_CENC_SUPPORT
        -DHI_PRODUCT_SM1_SM4_SUPPORT
        -DHI_PRODUCT_SM2_SUPPORT
        -DHI_PRODUCT_SM3_SUPPORT
        -DHI_PRODUCT_HMAC_SUPPORT
        -DHI_PRODUCT_RSA_SUPPORT
        -DHI_PRODUCT_ECC_SUPPORT
        -DHI_PRODUCT_CBC_MAC_SUPPORT
        -DHI_PRODUCT_MULTI_CIPHER_SUPPORT
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/include
        ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/pal/include
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/crys
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/pale
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/codesafe/src/crys/common/inc
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/codesafe/src/crys/rsa/crys_rsa/inc
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/codesafe/src/crys/rnd_dma
        ${PROJECT_SOURCE_DIR}/thirdparty/vendor/libdxcc/austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/inc
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/cenc
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/include

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/include

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/osal/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mem/sec_mmz/include
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/cenc/drv_cenc_v300.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/drv_symc_v300.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/drv_hash_v300.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/drv_pke_v200.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/drv_trng_v200.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/core/drv_lib.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_symc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_hash.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_trng.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_rsa.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_sm2.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/crypto/cryp_ecc.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_symc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_hash.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_rsa.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_trng.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_sm2.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_ecc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/kapi_dispatch.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/bignum.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/ecdh.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/ecdsa.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/ecp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/ecp_curves.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/md.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/rsa.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/rsa_internal.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/sha1.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/sha256.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/sha512.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/asn1parse.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/md_wrap.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/oid.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/platform_util.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/mbedtls/aes.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/ext_cmac.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/ext_hash.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/ext_ecc.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/ext_sm2.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/drivers/extend/ext_sm3.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/osal/drv_osal_init.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/osal/drv_osal_sys.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/compat/hi_drv_compat.c

        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_aes.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_hmac.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_rsa.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_rsa_prim.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_hash.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_rsa_kg.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_rnd_rom.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_cipher_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_rsa_build.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_ecpki_kg.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_ecdsa_sign.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_ecdsa_verify.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_ecpki_build.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_common_conv_endian.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_common_math.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/tee/src/crys_stub.c
    )
    if ("${CFG_HI_TEE_TEST_CIPHER_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS
            -DHI_SHA1_DISABLE
        )
        list(APPEND TEE_C_SOURCES
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_aes.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_kg.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_prim.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_rsa.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_hash.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_ecdsa.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_ecpki_build.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_crys_hmac.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_cts.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_cenc.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/test/test_main.c
        )
    endif()

endif()

if ("${CFG_HI_TEE_DEMO_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demo/tee_drv_demo.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demo/tee_drv_demo_func_test.c
    )
endif()

if ("${CFG_HI_TEE_SSM_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/ssm/tee_drv_ssm.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/ssm/iommu_tag_init.c
    )
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/api/include
    )
endif()

if ("${CFG_HI_TEE_OTP_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS -fstack-protector-all)
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/otp/drv_otp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/otp/drv_otp_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/otp/hal_otp.c
    )
    if ("${CFG_HI_TEE_OTP_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_SOURCES
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/otp/drv_otp_proc.c
        )
        list(APPEND TEE_C_FLAGS -DHI_OTP_TEST_SUPPORT)
    endif()
endif()

if ("${CFG_HI_TEE_KLAD_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/rkp
    )
    list(APPEND TEE_C_FLAGS
        -DHI_KLAD_PERF_SUPPORT
        -DHI_INT_SUPPORT
        -DKLAD_MODULE_ID_BASIC=\"data/${CFG_HI_TEE_CHIP_TYPE}/module_id_basic.txt\"
        -fstack-protector-all
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_sw.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_hw.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_hw_func.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_timestamp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_bitmap.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_klad_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/hal_klad.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/drv_hkl.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/rkp/drv_rkp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/rkp/drv_rkp_dbg.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/rkp/hal_rkp.c
    )
    if ("${CFG_ADVCA_NAGRA}" STREQUAL "y")
        list(APPEND TEE_C_SOURCES
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/cert/tee_drv_cert.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/cert/tee_drv_cert_intf.c
            ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/cert/tee_hal_cert.c
        )
        list(APPEND TEE_C_FLAGS
            -I${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/klad/nagra/cert
            -DHI_TEE_KLAD_CERT
            -DHI_KLAD_NAGRA_SUPPORT
            -DKLAD_MODULE_ID_NAGRA=\"./data/$(CFG_HI_TEE_CHIP_TYPE)/module_id_nagra.txt\"
        )
    endif()
endif()

if ("${CFG_HI_TEE_KEYSLOT_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_C_FLAGS -fstack-protector-all)
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/keyslot
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/keyslot/drv_keyslot.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/keyslot/drv_keyslot_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/keyslot/hal_keyslot.c
    )
endif()
if ("${CFG_HI_TEE_DEMUX_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/api/include
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/api/demux
    )
    if ("${CFG_HI_TEE_SMMU_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS -DDMX_SMMU_SUPPORT)
    endif()
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_drv_demux.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_drv_demux_utils.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_drv_demux_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_drv_demux_func.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_hal_demux.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/demux/tee_drv_demux_index.c
    )
endif()

if ("${CFG_HI_TEE_TSR2RCIPHER_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tsr2rcipher
    )
    if ("${CFG_HI_TEE_SMMU_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS -DTSR2RCIPHER_SMMU_SUPPORT)
    endif()
    list(APPEND TEE_C_FLAGS -DLOG_MODULE_ID=HI_ID_TSR2RCIPHER)
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tsr2rcipher/tee_drv_tsr2rcipher_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tsr2rcipher/tee_drv_tsr2rcipher.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tsr2rcipher/tee_drv_tsr2rcipher_func.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/tsr2rcipher/tee_hal_tsr2rcipher.c
    )
endif()

if ("${CFG_HI_TEE_PVR_SUPPORT}" STREQUAL "y")
    if ("${CFG_HI_TEE_SMMU_SUPPORT}" STREQUAL "y")
        list(APPEND TEE_C_FLAGS -DPVR_SMMU_SUPPORT)
    endif()
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/pvr
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/api/pvr
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/api/include
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/pvr/tee_drv_pvr_play.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/pvr/tee_drv_pvr.c
    )
endif()

if ("${CFG_HI_TEE_HDMITX_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmitx.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmitx_sys.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmitx_io.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmitx_hdcp2x.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmitx_hdcp1x.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmitx_ctrl.c
    )
endif()

if ("${CFG_HI_TEE_HDMIRX_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmirx
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmirx/hal
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmirx/product/v900es
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmirx.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmirx_ctrl.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmirx_hdcp.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/tee_drv_hdmirx_rpt.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmirx_comm.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmirx_ctrl.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/hdmitx/hal/tee_hal_hdmirx_hdcp.c
    )
endif()

if ("${CFG_HI_TEE_VFMW_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/vfmw
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/vfmw/tee_drv_vfmw.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/vfmw/tee_drv_vfmw_sign.c
    )
endif()

if ("${CFG_HI_TEE_COMMON_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/vfmw
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/common/tee_drv_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/common/bitmap.c
    )
endif()

if ("${CFG_HI_TEE_MAILBOX_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mailbox
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mailbox/mbx_common.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/mailbox/drv_mbx.c
    )
endif()

if ("${CFG_HI_TEE_DYNAMIC_TA_LOAD}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/taload
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/taload/tee_drv_taload.c
    )
endif()

if ("${CFG_HI_TEE_NPU_SUPPORT}" STREQUAL "y")
    list(APPEND TEE_INCLUDE_PATH
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu
    )
    list(APPEND TEE_C_SOURCES
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu/tee_drv_npu_intf.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu/tee_drv_npu_func.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu/tee_drv_npu_utils.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu/tee_drv_npu_pm.c
        ${PROJECT_SOURCE_DIR}/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/npu/tee_drv_npu_test_hwts.c
    )
endif()
