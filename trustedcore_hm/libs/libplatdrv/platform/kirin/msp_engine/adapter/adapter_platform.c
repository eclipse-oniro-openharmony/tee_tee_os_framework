/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter platform api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_common.h>
#include <adapter_ecc.h>
#include <adapter_rsa.h>
#include <adapter_rng.h>
#include <adapter_hmac.h>
#include <adapter_hash.h>
#include <adapter_cipher.h>
#include <hisee_aes.h>
#include <hisee_des.h>
#include <hisee_sm4.h>
#include <hisee_hash.h>
#include <hisee_hmac.h>
#include <common_utils.h>
#include <pal_libc.h>
#include <pal_log.h>
#include <common_sce.h>
#include <drv_module.h>

#define BSP_THIS_MODULE                   BSP_MODULE_SEC

int adapter_get_ctx_size(uint32_t alg_type)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	u32 ctx_size = 0;

	ret = adapter_symm_algo_convert(alg_type, &algo_type, NULL);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return 0;

	switch (algo_type) {
	case SYMM_ALGORITHM_AES:
		ctx_size = sizeof(struct hisee_aes_user_ctx);
		break;
	case SYMM_ALGORITHM_DES:
		ctx_size = sizeof(struct hisee_des_user_ctx);
		break;
	case SYMM_ALGORITHM_SM4:
		ctx_size = sizeof(struct hisee_sm4_user_ctx);
		break;
	case ADAPTER_ALGO_HASH:
		ctx_size = sizeof(struct hisee_hash_user_ctx);
		break;
	case ADAPTER_ALGO_HMAC:
		ctx_size = sizeof(struct hisee_hmac_user_ctx);
		break;
	default:
		PAL_ERROR("algo_type = %d error!\n", algo_type);
		ctx_size = 0;
		break;
	}
	return ctx_size;
}

int adapter_ctx_copy(uint32_t alg_type, const void *src_ctx, uint32_t src_size, void *dest_ctx, uint32_t dest_size)
{
	errno_t libc_ret = EINVAL;
	u32 ctx_size = 0;

	if(PAL_CHECK(!src_ctx || !dest_ctx))
		return ERR_API(ERRCODE_NULL);

	ctx_size = adapter_get_ctx_size(alg_type);
	if (PAL_CHECK(ctx_size == 0))
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(ctx_size != src_size || ctx_size > dest_size))
		return ERR_API(ERRCODE_PARAMS);

	libc_ret = memcpy_s(dest_ctx, dest_size, src_ctx, src_size);
	if (PAL_CHECK(libc_ret != EOK))
		return ERR_API(ERRCODE_MEMORY);

	return CRYPTO_SUCCESS;
}

PRIVATE const struct crypto_ops_t g_ops_list = {
	NULL,
	NULL,
	adapter_get_ctx_size,
	adapter_ctx_copy,
    NULL,
	adapter_hash_init,
	adapter_hash_update,
	adapter_hash_dofinal,
	adapter_hash_single,
	adapter_hmac_init,
	adapter_hmac_update,
	adapter_hmac_dofinal,
	adapter_hmac_single,
	adapter_cipher_init,
	adapter_cipher_update,
	adapter_cipher_dofinal,
	adapter_cipher_single,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	adapter_rsa_generate_keypair,
	adapter_rsa_encrypt,
	adapter_rsa_decrypt,
	adapter_rsa_sign_digest,
	adapter_rsa_verify_digest,
	adapter_ecc_generate_keypair,
	adapter_ecc_encrypt,
	adapter_ecc_decrypt,
	adapter_ecc_sign_digest,
	adapter_ecc_verify_digest,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

const struct crypto_ops_t *get_eps_ops(void)
{
	return &g_ops_list;
}

static int32_t mspe_adapt_init(void)
{
	return register_crypto_ops(EPS_CRYPTO_FLAG, &g_ops_list);
}

DECLARE_TC_DRV(
    crypto_mspe_adapt,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    mspe_adapt_init,
    NULL,
    NULL,
    NULL,
    NULL
);
