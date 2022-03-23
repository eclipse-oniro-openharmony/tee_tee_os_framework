#api_incs  :=
#api_srcs  :=
#api_flags :=

api_incs += .
api_incs += $(HI_TEE_OS_DIR)/hm-os/drivers/platdrv/platform/devchip/include
api_srcs += hi_tee_cipher.c mpi_cipher.c sys_cipher.c user_osal_lib.c

api_flags +=  -DHI_PRODUCT_SHA512_SUPPORT \
              -DHI_PRODUCT_SM2_SUPPORT \
              -DHI_PRODUCT_DH_SUPPORT \
              -DHI_PRODUCT_SYMC_CONFIG_EX_SUPPORT \
              -DHI_PRODUCT_AEAD_SUPPORT \
              -DHI_PRODUCT_CENC_SUPPORT \
              -DHI_PRODUCT_SHA512_SUPPORT \
              -DHI_PRODUCT_SM14_SUPPORT \
              -DHI_PRODUCT_RSA_SUPPORT \
              -DHI_PRODUCT_MULTI_CIPHER_SUPPORT

