/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter symm crypto api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_cipher.h>
#include <hisee_aes.h>
#include <hisee_des.h>
#include <hisee_sm4.h>
#include <common_utils.h>
#include <pal_log.h>
#include <hisee_symm_common.h>

#define BSP_THIS_MODULE          BSP_MODULE_SCE

PRIVATE u32 adater_direction_convert(uint32_t direction)
{
	u32 hisee_direction;

	switch (direction) {
	case ENC_MODE:
		hisee_direction = SYMM_DIRECTION_ENCRYPT;
		break;
	case DEC_MODE:
		hisee_direction = SYMM_DIRECTION_DECRYPT;
		break;
	default:
		hisee_direction = SYMM_DIRECTION_MAX;
		break;
	}
	return hisee_direction;
}

PRIVATE u32 adater_key_type_convert(uint32_t key_type)
{
	u32 hisee_key_type;

	switch (key_type) {
	case CRYPTO_KEYTYPE_DEFAULT:
	case CRYPTO_KEYTYPE_USER:
		hisee_key_type = SYMM_KEYTYPE_USER;
		break;
	default:
		hisee_key_type = SYMM_KEYTYPE_MAX;
		break;
	}
	return hisee_key_type;
}

PRIVATE err_bsp_t adapter_cipher_init_param_convert(uint32_t alg_type, const struct symmerit_key_t *key,
						    uint32_t direction, u32 *key_type, u32 *algo_type,
						    u32 *algo_mode, u32 *hisee_direction)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(!key))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_symm_algo_convert(alg_type, algo_type, algo_mode);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	*key_type = adater_key_type_convert(key->key_type);
	if (PAL_CHECK(*key_type == SYMM_KEYTYPE_MAX))
		return ERR_API(ERRCODE_PARAMS);

	*hisee_direction = adater_direction_convert(direction);
	if (PAL_CHECK(*hisee_direction == SYMM_DIRECTION_MAX))
		return ERR_API(ERRCODE_PARAMS);

	return BSP_RET_OK;
}

PRIVATE err_bsp_t adapter_aes_init(void *ctx, u32 algo_mode, u32 hisee_direction,
				   const struct symmerit_key_t *key, const struct memref_t *iv)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 key_type;

	key_type = adater_key_type_convert(key->key_type);
	if (PAL_CHECK(key_type == SYMM_KEYTYPE_MAX))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_aes_init(ctx, hisee_direction, algo_mode, SYMM_PADDING_NONE);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = hisee_aes_set_key(ctx, key_type, (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	if (iv) {
		ret = hisee_aes_set_iv(ctx, (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
	}
	return ret;
}

PRIVATE err_bsp_t adapter_des_init(void *ctx, u32 algo_mode, u32 hisee_direction,
				   const struct symmerit_key_t *key, const struct memref_t *iv)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 key_type;

	if (PAL_CHECK(key->key_size != SYMM_KEYLEN_24))
		return ERR_API(ERRCODE_PARAMS);

	key_type = adater_key_type_convert(key->key_type);
	if (PAL_CHECK(key_type == SYMM_KEYTYPE_MAX))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_des_init(ctx, hisee_direction, algo_mode, SYMM_PADDING_NONE);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = hisee_des_set_key(ctx, key_type, (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	if (iv) {
		ret = hisee_des_set_iv(ctx, (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
	}
	return ret;
}

PRIVATE err_bsp_t adapter_sm4_init(void *ctx, u32 algo_mode, u32 hisee_direction,
				   const struct symmerit_key_t *key, const struct memref_t *iv)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 key_type;

	key_type = adater_key_type_convert(key->key_type);
	if (PAL_CHECK(key_type == SYMM_KEYTYPE_MAX))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_sm4_init(ctx, hisee_direction, algo_mode, SYMM_PADDING_NONE);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = hisee_sm4_set_key(ctx, key_type, (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	if (iv) {
		ret = hisee_sm4_set_iv(ctx, (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
	}
	return ret;
}

int adapter_cipher_init(uint32_t alg_type, void *ctx, uint32_t direction,
			const struct symmerit_key_t *key, const struct memref_t *iv)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	u32 algo_mode = 0;
	u32 key_type = 0;
	u32 hisee_direction = 0;

	ret = adapter_cipher_init_param_convert(alg_type, key, direction, &key_type,
						&algo_type, &algo_mode, &hisee_direction);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	switch (algo_type) {
	case SYMM_ALGORITHM_AES:
		ret = adapter_aes_init(ctx, algo_mode, hisee_direction, key, iv);
		break;
	case SYMM_ALGORITHM_DES:
		ret = adapter_des_init(ctx, algo_mode, hisee_direction, key, iv);
		break;
	case SYMM_ALGORITHM_SM4:
		ret = adapter_sm4_init(ctx, algo_mode, hisee_direction, key, iv);
		break;
	default:
		PAL_ERROR("algo_type = %d error!\n", algo_type);
		return ERR_API(ERRCODE_UNSUPPORT);
	}

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_cipher_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_symm_ctx *pctx = (struct hisee_symm_ctx *)ctx;
	uint8_t *pdout = NULL;
	size_t  *pdoutlen = NULL;

	if (PAL_CHECK(!pctx || !data_in))
		return ERR_API(ERRCODE_NULL);

	if (data_out) {
		pdout = (uint8_t *)(uintptr_t)(data_out->buffer);
		pdoutlen = &data_out->size;
	}

	algo_type = pctx->algorithm;
	switch (algo_type) {
	case SYMM_ALGORITHM_AES:
		ret = hisee_aes_update(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, pdout, pdoutlen);
		break;
	case SYMM_ALGORITHM_DES:
		ret = hisee_des_update(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, pdout, pdoutlen);
		break;
	case SYMM_ALGORITHM_SM4:
		ret = hisee_sm4_update(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, pdout, pdoutlen);
		break;
	default:
		PAL_ERROR("algo_type = %d error!\n", algo_type);
		return ERR_API(ERRCODE_UNSUPPORT);
	}

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_cipher_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_symm_ctx *pctx = (struct hisee_symm_ctx *)ctx;

	if (PAL_CHECK(!pctx || !data_in || !data_out))
		return ERR_API(ERRCODE_NULL);

	algo_type = pctx->algorithm;
	switch (algo_type) {
	case SYMM_ALGORITHM_AES:
		ret = hisee_aes_dofinal(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
			(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
		break;
	case SYMM_ALGORITHM_DES:
		ret = hisee_des_dofinal(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
			(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
		break;
	case SYMM_ALGORITHM_SM4:
		ret = hisee_sm4_dofinal(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
			(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
		break;
	default:
		PAL_ERROR("algo_type = %d error!\n", algo_type);
		return ERR_API(ERRCODE_UNSUPPORT);
	}

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_cipher_single(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
			  const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
	struct hisee_aes_user_ctx ctx;
	int ret;

	ret = adapter_cipher_init(alg_type, &ctx, direction, key, iv);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	ret = adapter_cipher_dofinal(&ctx, data_in, data_out);
	if (PAL_CHECK(ret != CRYPTO_SUCCESS))
		return ret;

	return ret;
}

