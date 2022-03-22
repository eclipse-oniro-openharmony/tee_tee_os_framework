list(APPEND TEE_C_SOURCES
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher/hi_tee_cipher.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher/mpi_cipher.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher/sys_cipher.c
    ${PROJECT_SOURCE_DIR}/vendor/huanglong/libdevchip_api/cipher/user_osal_lib.c
)

list(APPEND TEE_INCLUDE_PATH
    ${PROJECT_SOURCE_DIR}/drivers/platdrv/platform/huanglong/include
)

list(APPEND TEE_C_FLAGS
    -DHI_PRODUCT_SHA512_SUPPORT
    -DHI_PRODUCT_SM2_SUPPORT
    -DHI_PRODUCT_DH_SUPPORT
    -DHI_PRODUCT_SYMC_CONFIG_EX_SUPPORT
    -DHI_PRODUCT_AEAD_SUPPORT
    -DHI_PRODUCT_CENC_SUPPORT
    -DHI_PRODUCT_SHA512_SUPPORT
    -DHI_PRODUCT_SM14_SUPPORT
    -DHI_PRODUCT_RSA_SUPPORT
    -DHI_PRODUCT_MULTI_CIPHER_SUPPORT
)
