/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter rsa keypair generate, rsa crypto and rsa signature api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_rsa.h>
#include <hisee_rsa.h>
#include <common_utils.h>
#include <pal_libc.h>
#include <pal_log.h>
#include <pal_memory.h>

#define BSP_THIS_MODULE                BSP_MODULE_RSA

#define ATTRIBUTE_ID_LEGAL(attr_id)    ((attr_id) == CRYPTO_ATTR_RSA_OAEP_LABEL || \
					(attr_id) == CRYPTO_ATTR_RSA_MGF1_HASH || \
					(attr_id) == CRYPTO_ATTR_RSA_PSS_SALT_LENGTH)

struct rsa_attr_id_convert_table {
	u32 adapter_attr_id;
	u32 hisee_attr_id;
};

PRIVATE const struct rsa_attr_id_convert_table g_rsa_attr_id_table[] = {
	{ CRYPTO_ATTR_RSA_OAEP_LABEL, HISEE_ATTR_RSA_OAEP_LABEL },
	{ CRYPTO_ATTR_RSA_MGF1_HASH, HISEE_ATTR_RSA_MGF1_HASH },
	{ CRYPTO_ATTR_RSA_PSS_SALT_LENGTH, HISEE_ATTR_RSA_PSS_SALT_LENGTH },
};

err_bsp_t adapter_rsa_attr_id_convert(uint32_t adapter_attr_id, u32 *hisee_attr_id)
{
	u32 i;

	if (PAL_CHECK(!hisee_attr_id))
		return ERR_API(ERRCODE_NULL);

	for (i = 0; i < ARRAY_SIZE(g_rsa_attr_id_table); i++) {
		if (g_rsa_attr_id_table[i].adapter_attr_id == adapter_attr_id) {
			*hisee_attr_id = g_rsa_attr_id_table[i].hisee_attr_id;
			return BSP_RET_OK;
		}
	}

	return ERR_API(ERRCODE_UNSUPPORT);
}

PRIVATE err_bsp_t adapter_param_check(const struct asymmetric_params_t *rsa_params)
{
	u32 i, param_count;
	struct crypto_attribute_t *adapter_attr = NULL;

	param_count = rsa_params->param_count;
	if (PAL_CHECK(param_count == 0 || param_count > PARAM_NUM_MAX || !rsa_params->attribute))
		return ERR_API(ERRCODE_PARAMS);

	struct crypto_attribute_t *tmp_attribute = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
	for (i = 0; i < param_count; i++) {
		adapter_attr = tmp_attribute + i;
		if (PAL_CHECK(!adapter_attr))
			return ERR_API(ERRCODE_NULL);

		if (PAL_CHECK(!ATTRIBUTE_ID_LEGAL(adapter_attr->attribute_id)))
			return ERR_API(ERRCODE_INVALID);
	}

	return BSP_RET_OK;
}

PRIVATE err_bsp_t adapter_param_convert(const struct asymmetric_params_t *rsa_params,
					struct hisee_attribute *hisee_param, u32 *param_cnt)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct crypto_attribute_t *adapter_attr = NULL;
	u32 i;
	u32 algo_type = 0;
	u32 algo_mode = 0;
	u32 attribute_id = 0;

	if (!rsa_params) {
		*param_cnt = 0;
		return BSP_RET_OK;
	}

	ret = adapter_param_check(rsa_params);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	struct crypto_attribute_t *tmp_attribute = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
	for (i = 0; i < rsa_params->param_count; i++) {
		adapter_attr = &(tmp_attribute[i]);
		if (adapter_attr->attribute_id == CRYPTO_ATTR_RSA_MGF1_HASH) {
			ret = adapter_symm_algo_convert(adapter_attr->content.value.a, &algo_type, &algo_mode);
			if (PAL_CHECK(ret != BSP_RET_OK || algo_type != ADAPTER_ALGO_HASH))
				return ret;
			hisee_param[i].content.value.a = algo_mode;
			hisee_param[i].content.value.b = 0;
		} else if (adapter_attr->attribute_id == CRYPTO_ATTR_RSA_OAEP_LABEL) {
			hisee_param[i].content.ref.buffer = (void *)(uintptr_t)adapter_attr->content.ref.buffer;
			hisee_param[i].content.ref.size = (u32)adapter_attr->content.ref.length;
		} else {
			hisee_param[i].content.value.a = adapter_attr->content.value.a;
			hisee_param[i].content.value.b = 0;
		}
		ret = adapter_rsa_attr_id_convert(adapter_attr->attribute_id, &attribute_id);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		hisee_param[i].attribute_id = attribute_id;
	}
	*param_cnt = rsa_params->param_count;
	return BSP_RET_OK;
}

PRIVATE void adapter_pubkey_convert(const struct rsa_pub_key_t *public_key, struct hisee_rsa_pubkey *pubkey)
{
	pubkey->width = BYTE2BIT(public_key->n_len);
	pubkey->n.pdata = (u8 *)public_key->n;
	pubkey->n.size = public_key->n_len;
	pubkey->e.pdata = (u8 *)public_key->e;
	pubkey->e.size = public_key->e_len;
}

PRIVATE void adapter_privkey_convert(const struct rsa_priv_key_t *private_key, struct hisee_rsa_privkey *privkey)
{
	privkey->width = BYTE2BIT(private_key->n_len);
	privkey->n.pdata = (u8 *)private_key->n;
	privkey->n.size = private_key->n_len;

	if (private_key->crt_mode == false) {
		privkey->key_type = ALG_RSA_STD_KEY;
		privkey->d.pdata = (u8 *)private_key->d;
		privkey->d.size = private_key->d_len;
	} else {
		privkey->key_type = ALG_RSA_CRT_KEY;
		privkey->p.pdata = (u8 *)private_key->p;
		privkey->p.size = private_key->p_len;
		privkey->q.pdata = (u8 *)private_key->q;
		privkey->q.size = private_key->q_len;
		privkey->dp.pdata = (u8 *)private_key->dp;
		privkey->dp.size = private_key->dp_len;
		privkey->dq.pdata = (u8 *)private_key->dq;
		privkey->dq.size = private_key->dq_len;
		privkey->qinv.pdata = (u8 *)private_key->qinv;
		privkey->qinv.size = private_key->qinv_len;
	}
}

int adapter_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
				 struct rsa_priv_key_t *key_pair)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_rsa_keypair keypair = {0};

	if (PAL_CHECK(!e_value || !key_pair))
		return ERR_API(ERRCODE_NULL);

	keypair.width = key_size;
	keypair.e.pdata = (uint8_t *)(uintptr_t)(e_value->buffer);
	keypair.e.size = e_value->size;
	keypair.n.pdata = key_pair->n;
	keypair.n.size = key_pair->n_len;

	if (crt_mode == false) {
		keypair.key_type = ALG_RSA_STD_KEY;
		keypair.d.pdata = key_pair->d;
		keypair.d.size = key_pair->d_len;
	} else {
		keypair.key_type = ALG_RSA_CRT_KEY;
		keypair.p.pdata = key_pair->p;
		keypair.p.size = key_pair->p_len;
		keypair.q.pdata = key_pair->q;
		keypair.q.size = key_pair->q_len;
		keypair.dp.pdata = key_pair->dp;
		keypair.dp.size = key_pair->dp_len;
		keypair.dq.pdata = key_pair->dq;
		keypair.dq.size = key_pair->dq_len;
		keypair.qinv.pdata = key_pair->qinv;
		keypair.qinv.size = key_pair->qinv_len;
	}

	ret = hisee_rsa_gen_key(&keypair);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = LIBC_MEM_CNV_ERRCODE(memcpy_s(key_pair->e, sizeof(key_pair->e), (void *)(uintptr_t)e_value->buffer, e_value->size));
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	key_pair->e_len = e_value->size;
	key_pair->crt_mode = crt_mode;
	return CRYPTO_SUCCESS;
}

int adapter_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
			const struct asymmetric_params_t *rsa_params,
			const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_rsa_pubkey pubkey = {0};
	struct hisee_attribute param[PARAM_NUM_MAX] = { {0} };
	u32 param_cnt = 0;

	if (PAL_CHECK(!public_key || !data_in || !data_out))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_asymm_algo_convert(alg_type, &algo_type);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	adapter_pubkey_convert(public_key, &pubkey);

	ret = adapter_param_convert(rsa_params, param, &param_cnt);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_rsa_encrypt(algo_type, &pubkey, param, param_cnt,
		(uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
		(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
			const struct asymmetric_params_t *rsa_params,
			const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_rsa_privkey privkey = {0};
	struct hisee_attribute param[PARAM_NUM_MAX] = { {0} };
	u32 param_cnt = 0;

	if (PAL_CHECK(!private_key || !data_in || !data_out))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_asymm_algo_convert(alg_type, &algo_type);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	adapter_privkey_convert(private_key, &privkey);

	ret = adapter_param_convert(rsa_params, param, &param_cnt);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_rsa_decrypt(algo_type, &privkey, param, param_cnt,
		(uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
		(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
			    const struct asymmetric_params_t *rsa_params,
			    const struct memref_t *digest, struct memref_t *signature)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_rsa_privkey privkey = {0};
	struct hisee_attribute param[PARAM_NUM_MAX] = { {0} };
	u32 param_cnt = 0;

	if (PAL_CHECK(!private_key || !digest || !signature))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_asymm_algo_convert(alg_type, &algo_type);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	adapter_privkey_convert(private_key, &privkey);

	ret = adapter_param_convert(rsa_params, param, &param_cnt);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_rsa_sign(algo_type, &privkey, param, param_cnt,
		(uint8_t *)(uintptr_t)(digest->buffer), digest->size,
		(uint8_t *)(uintptr_t)(signature->buffer), &signature->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
			      const struct asymmetric_params_t *rsa_params,
			      const struct memref_t *digest, const struct memref_t *signature)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u32 algo_type = 0;
	struct hisee_rsa_pubkey pubkey = {0};
	struct hisee_attribute param[PARAM_NUM_MAX] = { {0} };
	u32 param_cnt = 0;

	if (PAL_CHECK(!public_key || !digest || !signature))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_asymm_algo_convert(alg_type, &algo_type);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	adapter_pubkey_convert(public_key, &pubkey);

	ret = adapter_param_convert(rsa_params, param, &param_cnt);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_rsa_verify(algo_type, &pubkey, param, param_cnt,
		(uint8_t *)(uintptr_t)(digest->buffer), digest->size,
		(uint8_t *)(uintptr_t)(signature->buffer), signature->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

