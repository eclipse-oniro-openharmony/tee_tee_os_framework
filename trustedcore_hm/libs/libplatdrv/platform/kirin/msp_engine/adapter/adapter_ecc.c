/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter ecc keypair generate, ecc crypto and ecc signature api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_ecc.h>
#include <common_ecc.h>
#include <hisee_sm2.h>
#include <common_utils.h>
#include <pal_log.h>
#include <tee_log.h>

#define BSP_THIS_MODULE          BSP_MODULE_ECC

#define SM2_C1_HEAD              0x04
#define SM2_C1_HEAD_LEN          0x01

PRIVATE u32 adater_ecc_curveid_convert(uint32_t curve_id)
{
	u32 hisee_curve_id;

	switch (curve_id) {
	case ECC_CURVE_SM2:
		hisee_curve_id = CURVE_ID_SM2P256V1;
		break;
	default:
		hisee_curve_id = CURVE_ID_MAX;
		break;
	}
	return hisee_curve_id;
}

PRIVATE err_bsp_t adapter_ecc_crypt_param_check(uint32_t alg_type, uint32_t domain_id,
						const struct asymmetric_params_t *ec_params)
{
	if (PAL_CHECK(ec_params || domain_id != ECC_CURVE_SM2))
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(alg_type != (uint32_t)CRYPTO_TYPE_SM2_PKE))
		return ERR_API(ERRCODE_PARAMS);

	return BSP_RET_OK;
}

PRIVATE err_bsp_t adapter_ecc_sign_param_check(uint32_t alg_type, uint32_t domain_id,
					       const struct asymmetric_params_t *ec_params)
{
	if (PAL_CHECK(ec_params || domain_id != ECC_CURVE_SM2))
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(alg_type != CRYPTO_TYPE_SM2_DSA_SM3))
		return ERR_API(ERRCODE_PARAMS);

	return BSP_RET_OK;
}

int adapter_ecc_generate_keypair(uint32_t keysize, uint32_t curve_id,
				 struct ecc_pub_key_t *public_key,
				 struct ecc_priv_key_t *private_key)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_ecc_keypair keypair = {0};

	if (PAL_CHECK(!public_key || !private_key))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(curve_id != ECC_CURVE_SM2))
		return ERR_API(ERRCODE_PARAMS);

	keypair.curve_id = adater_ecc_curveid_convert(curve_id);
	keypair.width = keysize;
	keypair.priv.pdata = private_key->r;
	keypair.priv.size = private_key->r_len;
	keypair.pubx.pdata = public_key->x;
	keypair.pubx.size = public_key->x_len;
	keypair.puby.pdata = public_key->y;
	keypair.puby.size = public_key->y_len;

	ret = hisee_sm2_gen_key(&keypair);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	public_key->domain_id = curve_id;
	private_key->domain_id = curve_id;

	return CRYPTO_SUCCESS;
}

int adapter_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
			const struct asymmetric_params_t *ec_params,
			const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_ecc_pubkey pubkey = {0};
	u32 doutlen;

	if (PAL_CHECK(!public_key || !data_in || !data_out ||
		      data_out->size < SM2_C1_HEAD_LEN || !data_out->buffer))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_ecc_crypt_param_check(alg_type, public_key->domain_id, ec_params);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pubkey.curve_id = adater_ecc_curveid_convert(public_key->domain_id);
	pubkey.width = SM2_KEY_WIDTH;
	pubkey.pubx.pdata = (u8 *)public_key->x;
	pubkey.pubx.size = public_key->x_len;
	pubkey.puby.pdata = (u8 *)public_key->y;
	pubkey.puby.size = public_key->y_len;

	doutlen = data_out->size - SM2_C1_HEAD_LEN;
	ret = hisee_sm2_encrypt(&pubkey, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
				(uint8_t *)(uintptr_t)(data_out->buffer) + SM2_C1_HEAD_LEN, &doutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	((uint8_t *)(uintptr_t)(data_out->buffer))[0] = SM2_C1_HEAD;
	data_out->size = doutlen + SM2_C1_HEAD_LEN;
	return CRYPTO_SUCCESS;
}

int adapter_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
			const struct asymmetric_params_t *ec_params,
			const struct memref_t *data_in, struct memref_t *data_out)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_ecc_privkey privkey = {0};

	if (PAL_CHECK(!private_key || !data_in || !data_out || data_in->size < SM2_C1_HEAD_LEN ||
		      !data_in->buffer || ((uint8_t *)(uintptr_t)(data_in->buffer))[0] != SM2_C1_HEAD))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_ecc_crypt_param_check(alg_type, private_key->domain_id, ec_params);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	privkey.curve_id = adater_ecc_curveid_convert(private_key->domain_id);
	privkey.width = SM2_KEY_WIDTH;
	privkey.priv.pdata = (u8 *)private_key->r;
	privkey.priv.size = private_key->r_len;

	ret = hisee_sm2_decrypt(&privkey, (uint8_t *)(uintptr_t)(data_in->buffer) + SM2_C1_HEAD_LEN, data_in->size - SM2_C1_HEAD_LEN,
				(uint8_t *)(uintptr_t)(data_out->buffer), &data_out->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
			    const struct asymmetric_params_t *ec_params,
			    const struct memref_t *digest, struct memref_t *signature)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_ecc_privkey privkey = {0};

	if (PAL_CHECK(!private_key || !digest || !signature))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_ecc_sign_param_check(alg_type, private_key->domain_id, ec_params);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	privkey.curve_id = adater_ecc_curveid_convert(private_key->domain_id);
	privkey.width = SM2_KEY_WIDTH;
	privkey.priv.pdata = (u8 *)private_key->r;
	privkey.priv.size = private_key->r_len;

	ret = hisee_sm2_digest_sign(&privkey, (uint8_t *)(uintptr_t)(digest->buffer), digest->size,
		(uint8_t *)(uintptr_t)(signature->buffer), &signature->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

int adapter_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
			      const struct asymmetric_params_t *ec_params,
			      const struct memref_t *digest, const struct memref_t *signature)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_ecc_pubkey pubkey = {0};

	if (PAL_CHECK(!public_key || !digest || !signature))
		return ERR_API(ERRCODE_NULL);

	ret = adapter_ecc_sign_param_check(alg_type, public_key->domain_id, ec_params);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pubkey.curve_id = adater_ecc_curveid_convert(public_key->domain_id);
	pubkey.width = SM2_KEY_WIDTH;
	pubkey.pubx.pdata = (u8 *)public_key->x;
	pubkey.pubx.size = public_key->x_len;
	pubkey.puby.pdata = (u8 *)public_key->y;
	pubkey.puby.size = public_key->y_len;

	ret = hisee_sm2_digest_verify(&pubkey, (uint8_t *)(uintptr_t)(digest->buffer), digest->size,
		(uint8_t *)(uintptr_t)(signature->buffer), signature->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return CRYPTO_SUCCESS;
}

