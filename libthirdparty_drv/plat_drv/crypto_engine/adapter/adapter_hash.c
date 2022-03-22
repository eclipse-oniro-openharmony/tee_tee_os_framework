/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter hash api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_hash.h>
#include <hisee_hash.h>
#include <pal_log.h>

#define BSP_THIS_MODULE                   BSP_MODULE_HASH

int adapter_hash_init(void *ctx, uint32_t alg_type)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hash_user_ctx *pctx = (struct hisee_hash_user_ctx *)ctx;
	u32 algo_mode = 0;

	ret = adapter_symm_algo_convert(alg_type, NULL, &algo_mode);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	ret = hisee_hash_init(pctx, algo_mode);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hash_update(void *ctx, const struct memref_t *data_in)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hash_user_ctx *pctx = (struct hisee_hash_user_ctx *)ctx;

	if (PAL_CHECK(!data_in))
		return CRYPTO_BAD_PARAMETERS;

	ret = hisee_hash_update(pctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hash_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hash_user_ctx *pctx = (struct hisee_hash_user_ctx *)ctx;

	if (PAL_CHECK(!data_out))
		return CRYPTO_BAD_PARAMETERS;

	if (!data_in)
		ret = hisee_hash_dofinal(pctx, NULL, 0,
					 (uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	else
		ret = hisee_hash_dofinal(pctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
					 (uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hash_single(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
	struct hisee_hash_user_ctx ctx;
	int ret;

	ret = adapter_hash_init(&ctx, alg_type);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	ret = adapter_hash_dofinal(&ctx, data_in, data_out);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	return ret;
}

