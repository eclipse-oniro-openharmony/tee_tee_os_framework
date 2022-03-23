/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter hmac api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_hmac.h>
#include <hisee_hmac.h>
#include <pal_log.h>

#define BSP_THIS_MODULE                 BSP_MODULE_MAC

int adapter_hmac_init(uint32_t alg_type, void *ctx, const struct symmerit_key_t *key)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hmac_user_ctx *pctx = (struct hisee_hmac_user_ctx *)ctx;
	u32 algo_mode = 0;

	if (PAL_CHECK(!key))
		return CRYPTO_BAD_PARAMETERS;

	if (PAL_CHECK(key->key_type != CRYPTO_KEYTYPE_DEFAULT && key->key_type != CRYPTO_KEYTYPE_USER))
		return CRYPTO_BAD_PARAMETERS;

	ret = adapter_symm_algo_convert(alg_type, NULL, &algo_mode);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	ret = hisee_hmac_init(pctx, algo_mode, (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hmac_update(void *ctx, const struct memref_t *data_in)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hmac_user_ctx *pctx = (struct hisee_hmac_user_ctx *)ctx;

	if (PAL_CHECK(!data_in))
		return CRYPTO_BAD_PARAMETERS;

	ret = hisee_hmac_update(pctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hmac_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_hmac_user_ctx *pctx = (struct hisee_hmac_user_ctx *)ctx;

	if (PAL_CHECK(!data_out))
		return CRYPTO_BAD_PARAMETERS;

	if (!data_in)
		ret = hisee_hmac_dofinal(pctx, NULL, 0,
					 (uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	else
		ret = hisee_hmac_dofinal(pctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
					 (uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return CRYPTO_BAD_PARAMETERS;

	return CRYPTO_SUCCESS;
}

int adapter_hmac_single(uint32_t alg_type, const struct symmerit_key_t *key,
			const struct memref_t *data_in, struct memref_t *data_out)
{
	struct hisee_hmac_user_ctx ctx;
	int ret;

	ret = adapter_hmac_init(alg_type, &ctx, key);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	ret = adapter_hmac_dofinal(&ctx, data_in, data_out);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	return ret;
}

