/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cipher algorithm interface for china DRM
 * Author: s00294296
 * Create: 2019-11-04
 */
#include "cdrmr_cipher.h"
#include <cdrm_runtime_env.h>
#include <common_sce.h>
#include <api_cipher.h>
#include <pal_log.h>
#include <cdrmr_common.h>

#define BSP_THIS_MODULE BSP_MODULE_SCE

/* get crypto mode */
static u32 cdrmr_cipher_get_mode(CDRMR_Symmetric_Crypto_Algorithm algo)
{
	switch (algo) {
	case CDRMR_ALG_SM4_CBC_NOPAD:
		return SYMM_MODE_CBC;
	case CDRMR_ALG_SM4_CTR:
		return SYMM_MODE_CTR;
	case CDRMR_ALG_SM4_ECB_NOPAD:
		return SYMM_MODE_ECB;
	default:
		PAL_ERROR("error mode = %d\n", algo);
		return SYMM_MODE_UNKNOWN;
	}
}

/* get crypto algorithm */
static u32 cdrmr_cipher_get_algo(CDRMR_Symmetric_Crypto_Algorithm algo)
{
	switch (algo) {
	case CDRMR_ALG_SM4_CBC_NOPAD:
	case CDRMR_ALG_SM4_CTR:
	case CDRMR_ALG_SM4_ECB_NOPAD:
		return SYMM_ALGORITHM_SM4;
	default:
		PAL_ERROR("error algo = %d\n", algo);
		return SYMM_ALGORITHM_UNKNOWN;
	}
}

/* init struct api_cipher_init_s */
static void cdrmr_crypto_init(api_cipher_init_s *pcipher_init,
			      CDRMR_Symmetric_Crypto_Algorithm algo, u32 direction,
			      unsigned char *pkey, unsigned int keylen,
			      unsigned char *piv, unsigned int ivlen)
{
	pcipher_init->algorithm = cdrmr_cipher_get_algo(algo);
	pcipher_init->mode      = cdrmr_cipher_get_mode(algo);
	pcipher_init->direction = direction;
	pcipher_init->keytype   = API_CIPHER_KEYTYPE_USER_KEY;
	pcipher_init->pkey      = pkey;
	pcipher_init->width     = BYTE2BIT(keylen);
	pcipher_init->piv       = piv;
	pcipher_init->ivlen     = ivlen;
}

/* check algorithm and mode params */
static err_bsp_t cdrmr_crypto_params_check(CDRMR_Symmetric_Crypto_Algorithm algo)
{
	u32 mode, algorithm;

	mode = cdrmr_cipher_get_mode(algo);
	PAL_CHECK_RETURN(mode == SYMM_MODE_UNKNOWN, ERR_API(ERRCODE_PARAMS));

	algorithm = cdrmr_cipher_get_algo(algo);
	PAL_CHECK_RETURN(algorithm == SYMM_ALGORITHM_UNKNOWN, ERR_API(ERRCODE_PARAMS));

	return BSP_RET_OK;
}

static err_bsp_t cdrmr_crypto_symmetric_cipher(CDRMR_Symmetric_Crypto_Algorithm algo, u32 direction,
					       unsigned char *pkey, unsigned int keylen,
					       unsigned char *piv, unsigned int ivlen,
					       unsigned char *pdin, unsigned int dinlen,
					       unsigned char *pdout, unsigned int *pdoutlen)
{
	int ret = ERR_API(ERRCODE_UNKNOWN);
	api_cipher_ctx_s cipher_ctx = {0};
	api_cipher_init_s cipher_init = {0};

	ret = cdrmr_crypto_params_check(algo);
	PAL_ERR_RETURN(ret);

	cdrmr_crypto_init(&cipher_init, algo, direction, pkey, keylen, piv, ivlen);
	ret = api_cipher_init(&cipher_ctx, &cipher_init);
	PAL_ERR_RETURN(ret);

	ret = api_cipher_dofinal(&cipher_ctx, pdin, dinlen, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return ret;
}

/**
 * @brief     : general symmetric encrypt
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, the length of iv
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_crypto_symmetric_encrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
				   unsigned char *pkey, unsigned int keylen,
				   unsigned char *piv, unsigned int ivlen,
				   unsigned char *pdin, unsigned int dinlen,
				   unsigned char *pdout, unsigned int *pdoutlen)
{
	int ret = ERR_API(ERRCODE_UNKNOWN);
	u32 direction = SYMM_DIRECTION_ENCRYPT;

	ret = cdrmr_crypto_symmetric_cipher(algo, direction, pkey, keylen, piv,
					    ivlen, pdin, dinlen, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief     : general symmetric decrypt
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, the length of iv
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_crypto_symmetric_decrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
				   unsigned char *pkey, unsigned int keylen,
				   unsigned char *piv, unsigned int ivlen,
				   unsigned char *pdin, unsigned int dinlen,
				   unsigned char *pdout, unsigned int *pdoutlen)
{
	int ret = ERR_API(ERRCODE_UNKNOWN);
	u32 direction = SYMM_DIRECTION_DECRYPT;

	ret = cdrmr_crypto_symmetric_cipher(algo, direction, pkey, keylen, piv,
					    ivlen, pdin, dinlen, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief     : configure algorithm, key, iv to user context
 * @param[in] : puser_ctx, the user context
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the byte length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, the byte length of iv
 * @return    : 0 if successful, others fail
 */
int cdrmr_cipher_config_handle(struct cdrmr_cipher_user_ctx *puser_ctx,
			       CDRMR_Symmetric_Crypto_Algorithm algo,
			       unsigned char *pkey, unsigned int keylen,
			       unsigned char *piv, unsigned int ivlen)
{
	api_cipher_ctx_s *cipher_ctx = (api_cipher_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);
	api_cipher_init_s cipher_init = {0};
	u32 direction = SYMM_DIRECTION_DECRYPT; /* default value */

	ret = cdrmr_crypto_params_check(algo);
	PAL_ERR_RETURN(ret);

	cdrmr_crypto_init(&cipher_init, algo, direction, pkey, keylen, piv, ivlen);
	ret = api_cipher_init(cipher_ctx, &cipher_init);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief     : audio symmetric decrypt
 * @param[in] : puser_ctx, the user context
 * @param[in] : algo, algotirhm and mode, repeat with cdrmr_cipher_config_handle
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_cipher_cenc_decrypt(struct cdrmr_cipher_user_ctx *puser_ctx,
			      CDRMR_Cenc_Algorithm algo, unsigned char *pdin,
			      unsigned int dinlen, unsigned char *pdout,
			      unsigned int *pdoutlen)
{
	api_cipher_ctx_s *cipher_ctx = (api_cipher_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);

	UNUSED(algo);
	PAL_CHECK_RETURN(!cipher_ctx, ERR_HAL(ERRCODE_NULL));

	cipher_ctx->direction = SYMM_DIRECTION_DECRYPT;
	cipher_ctx->keytype = API_CIPHER_KEYTYPE_USER_VIDEO;
	ret = api_cipher_dofinal(cipher_ctx, pdin, dinlen, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

