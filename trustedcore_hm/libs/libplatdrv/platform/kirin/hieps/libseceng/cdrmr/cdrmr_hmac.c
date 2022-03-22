/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hmac algorithm interface for china DRM
 * Author: s00294296
 * Create: 2019-11-04
 */
#include "cdrmr_hmac.h"
#include <cdrm_runtime_env.h>
#include <common_sce.h>
#include <api_hmac.h>
#include <cdrmr_common.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE BSP_MODULE_SCE

static u32 cdrmr_crypto_hmac_get_algo(CDRMR_HMAC_Algorithm algo)
{
	switch (algo) {
	case CDRMR_ALG_HMAC_SM3:
		return SYMM_ALGORITHM_SM3;
	default:
		PAL_ERROR("error algo = %d\n", algo);
		return SYMM_ALGORITHM_UNKNOWN;
	}
}

/**
 * @brief      : configure algorithm, key to the user context
 * @param[in]  : algo, algorithm
 * @param[in]  : pkey, the point of key
 * @param[in]  : keylen, the length of key
 * @param[in]  : puser_ctx, the user context
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hmac_init(CDRMR_HMAC_Algorithm algo, unsigned char *pkey,
			   unsigned int keylen, struct cdrmr_hmac_user_ctx *puser_ctx)
{
	api_hmac_ctx_s *pctx = (api_hmac_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algorithm;

	algorithm = cdrmr_crypto_hmac_get_algo(algo);
	ret = api_hmac_init(pctx, algorithm, pkey, keylen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief      : hmac update
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdin, the point of input data
 * @param[in]  : dinlen, the length of input data
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hmac_update(struct cdrmr_hmac_user_ctx *puser_ctx,
			     unsigned char *pdin, unsigned int dinlen)
{
	api_hmac_ctx_s *pctx = (api_hmac_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);
	pal_master_addr_t din_addr = pdin;

	ret = api_hmac_update(pctx, din_addr, dinlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief      : hmac calculation of the last data
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdout, the point of output data
 * @param[in]  : pdoutlen, the point of output data length
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hmac_dofinal(struct cdrmr_hmac_user_ctx *puser_ctx,
			      unsigned char *pdout, unsigned int *pdoutlen)
{
	api_hmac_ctx_s *pctx = (api_hmac_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);
	const pal_master_addr_t pdin = 0;

	ret = api_hmac_dofinal(pctx, pdin, 0, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

