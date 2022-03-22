/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hash algorithm interface for china DRM
 * Author: s00294296
 * Create: 2019-11-04
 */
#include "cdrmr_hash.h"
#include <cdrm_runtime_env.h>
#include <common_sce.h>
#include <api_hash.h>
#include <cdrmr_common.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE BSP_MODULE_SCE

static u32 cdrmr_crypto_hash_get_algo(CDRMR_HASH_Algorithm algo)
{
	switch (algo) {
	case CDRMR_ALG_SM3:
		return SYMM_ALGORITHM_SM3;
	default:
		PAL_ERROR("error algo = %d\n", algo);
		return SYMM_ALGORITHM_UNKNOWN;
	}
}

/**
 * @brief      : configure algorithm to the user context
 * @param[in]  : algo, algorithm
 * @param[in]  : puser_ctx, the user context
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_init(CDRMR_HASH_Algorithm algo,
			   struct cdrmr_hash_user_ctx *puser_ctx)
{
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)puser_ctx;
	int ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algorithm;

	algorithm = cdrmr_crypto_hash_get_algo(algo);
	if (algorithm == SYMM_ALGORITHM_UNKNOWN)
		return ERR_API(ERRCODE_PARAMS);

	ret = api_hash_init(pctx, algorithm);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief      : hash update
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdin, the point of input data
 * @param[in]  : dinlen, the length of input data
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_update(struct cdrmr_hash_user_ctx *puser_ctx,
			     unsigned char *pdin, unsigned int dinlen)
{
	int ret = ERR_API(ERRCODE_UNKNOWN);
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)puser_ctx;
	pal_master_addr_t din_addr = pdin;

	PAL_CHECK_RETURN(dinlen > MAX_DATA_SUPPORT, ERR_API(ERRCODE_PARAMS));

	/* call agent */
	ret = api_hash_update(pctx, din_addr, dinlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

/**
 * @brief      : hash calculation of the last data
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdout, the point of output data
 * @param[in]  : pdoutlen, the point of output data length
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_dofinal(struct cdrmr_hash_user_ctx *puser_ctx,
			      unsigned char *pdout, unsigned int *pdoutlen)
{
	int ret = ERR_API(ERRCODE_UNKNOWN);
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)puser_ctx;
	const pal_master_addr_t pdin = 0;

	/* call agent */
	ret = api_hash_dofinal(pctx, pdin, 0, pdout, pdoutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

