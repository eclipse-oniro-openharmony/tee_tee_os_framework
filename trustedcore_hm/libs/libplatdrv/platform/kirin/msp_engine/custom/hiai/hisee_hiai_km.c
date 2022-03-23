/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: custom hiai km func
 * Author     : security-engine
 * Create     : 2020/04/20
 */
#include <hisee_hiai.h>
#include <seceng_plat.h>
#include <bn_basic.h>
#include <ec_fp_smpl.h>
#include <hisee_km.h>
#include <hisee_aes.h>
#include <hisee_hash.h>
#include <hisee_ecc_common.h>
#include "hisee_hiai_inner.h"

/* set the module to which the file belongs
 *  each .C file needs to be configured
 */
#define BSP_THIS_MODULE BSP_MODULE_KM

#define HIAI_DERIVE_PREFIX  (0x49416948) /* HiAI */
#define HIAI_DERIVE_LEN     SYMM_IVLEN_AES
#define HIAI_DERIVE_TOTAL   (HIAI_DERIVE_LEN + HIAI_DERIVE_LEN)

#define HIAI_EC_KEYLEN      BIT2BYTE(ECC_STDWIDTH_256)

PRIVATE err_bsp_t hisee_hiai_key_derive(const struct hisee_hiai_data *pdata,
					u8 *pdout, u32 *pdoutlen)
{
	u32 prefix0 = 0;
	u32 prefix1 = 0;
	u32 keylen = *pdoutlen;
	const struct basic_data *psrc = NULL;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(pdata->keytype != SYMM_KEYTYPE_GID))
		return ERR_API(ERRCODE_UNSUPPORT);

	psrc = &pdata->derivein;
	if (PAL_CHECK(!psrc->pdata || psrc->size != HIAI_DERIVE_TOTAL))
		return ERR_API(ERRCODE_PARAMS);

	WORD_SET(&prefix0, psrc->pdata);
	WORD_SET(&prefix1, &psrc->pdata[HIAI_DERIVE_LEN]);
	if (PAL_CHECK(prefix0 != HIAI_DERIVE_PREFIX || prefix1 != HIAI_DERIVE_PREFIX))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_derive_readable_key(pdata->keytype,
					psrc->pdata,
					HIAI_DERIVE_LEN,
					pdout, &keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pdout += keylen;
	*pdoutlen -= keylen;
	ret = hisee_derive_readable_key(pdata->keytype,
					&psrc->pdata[HIAI_DERIVE_LEN],
					HIAI_DERIVE_LEN,
					pdout, pdoutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	*pdoutlen += keylen;
	return ret;
}

PRIVATE err_bsp_t hisee_hiai_key_decrypt(const struct hisee_hiai_data *pdata,
					 const u8 *pkey, u32 keylen,
					 const u8 *pdin, u32 dinlen,
					 u8 *pdout, u32 *pdoutlen)
{
	struct hisee_aes_user_ctx ctx;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(pdata->alg != SYMM_ALGORITHM_AES ||
		      keylen != SYMM_KEYLEN_32 ||
		      !pdin || dinlen != HIAI_EC_KEYLEN))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_aes_init(&ctx, SYMM_DIRECTION_DECRYPT,
			     pdata->mode, SYMM_PADDING_NONE);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_aes_set_key(&ctx, SYMM_KEYTYPE_USER, pkey, keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_aes_set_iv(&ctx, pdata->iv.pdata, pdata->iv.size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_aes_dofinal(&ctx, pdin, dinlen, pdout, pdoutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	if (PAL_CHECK(*pdoutlen != HIAI_EC_KEYLEN))
		return ERR_API(ERRCODE_INVALID);

	return ret;
}

PRIVATE err_bsp_t hisee_hiai_key_verify(const struct hisee_hiai_data *pdata,
					const u8 *pkey, u32 keylen)
{
	u8 digest[SYMM_OUTLEN_SHA256] = {0};
	u32 len = sizeof(digest);
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(pdata->vtype != HIAI_VERIFY_SHA256))
		return ERR_API(ERRCODE_UNSUPPORT);

	if (PAL_CHECK(!pdata->vvalue.pdata))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_hash_single(SYMM_ALGORITHM_SHA256, pkey, keylen, digest, &len);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	if (PAL_CHECK(pdata->vvalue.size != len))
		return ERR_API(ERRCODE_VERIFY);

	ret = pal_mem_equ(pdata->vvalue.pdata, digest, len);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ERR_API(ERRCODE_VERIFY);
	return ret;
}

PRIVATE err_bsp_t hisee_hiai_ecdh(const struct ec_curve_group_fp *pcurve,
				  struct bn_data *pmul_k,
				  struct point_aff_cord *ppub_k,
				  u8 *pdout, u32 doutlen)
{
	struct bn_data point_x = {0};
	struct bn_data point_y = {0};
	struct point_aff_cord pk = {
		.px = &point_x,
		.py = &point_y,
	};
	struct basic_data dh_key = {0};
	u32 keylen;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	keylen = BIT2BYTE(pcurve->pbase->width);
	dh_key.size = keylen + keylen;
	if (PAL_CHECK(doutlen == 0 || doutlen > dh_key.size))
		return ERR_API(ERRCODE_PARAMS);

	dh_key.pdata = pal_malloc(dh_key.size);
	if (PAL_CHECK(!dh_key.pdata))
		return ERR_API(ERRCODE_MEMORY);

	ret = bn_init(&point_x, dh_key.pdata, keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

	ret = bn_init(&point_y, &dh_key.pdata[keylen], keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

	ret = pcurve->pfun->point_mul(pcurve, ppub_k, pmul_k, &pk);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

	ret = LIBC_MEM_CNV_ERRCODE(memcpy_s(pdout, doutlen, dh_key.pdata, doutlen));
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

end_handler:
	if (dh_key.pdata) {
		(void)memset_s(dh_key.pdata, dh_key.size, 0, dh_key.size);
		pal_free(dh_key.pdata);
	}

	return ret;
}

PRIVATE err_bsp_t hisee_hiai_ecdh_compute(const struct hisee_ecc_pubkey *ppubkey,
					  const u8 *privkey, u32 keylen,
					  u8 *pdout, u32 doutlen)
{
	struct bn_data mul_k = {0};
	struct hisee_ecc_pubkey_bn key_bn = {0};
	struct point_aff_cord pt = { &key_bn.pubx, &key_bn.puby};
	struct ec_curve_group_fp *pcurve = NULL;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(ppubkey->curve_id != CURVE_ID_BRAINPOOLP256R1))
		return ERR_API(ERRCODE_UNSUPPORT);

	ret = bn_init(&mul_k, (u8 *)privkey, keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_ecc_pubkey2bndata(ppubkey, &key_bn);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pcurve = ec_group_fp_new();
	if (PAL_CHECK(!pcurve))
		return ERR_API(ERRCODE_MEMORY);

	ret = ec_group_fp_init_by_id(ppubkey->curve_id, pcurve);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

	ret = ecc_check_pubkey(&key_bn, pcurve);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

	ret = hisee_hiai_ecdh(pcurve, &mul_k, &pt, pdout, doutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handler;

end_handler:
	ec_group_fp_free(pcurve);
	return ret;
}

/**
 * @brief      : hiai key compute
 * @param[in]  : pdata    hiai data information from ::struct hisee_hiai_data
 * @param[in]  : pdin     ecc private key ciphertext
 * @param[in]  : dinlen   key ciphertext bytes length
 * @param[out] : pdout    output buffer for hiai key compute
 * @param[in]  : doutlen  output key bytes length
 */
err_bsp_t hisee_hiai_key_do_compute(const struct hisee_hiai_data *pdata,
				    const u8 *pdin, u32 dinlen,
				    u8 *pdout, u32 doutlen)
{
	u32 len, keylen;
	u8 tmp[HIAI_EC_KEYLEN] = {0};
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(!pdata || !pdout))
		return ERR_API(ERRCODE_NULL);

	/* step1. derive hiai key(256) */
	keylen = sizeof(tmp);
	ret = hisee_hiai_key_derive(pdata, tmp, &keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* step2. ecc privkey decrypt */
	len = sizeof(tmp);
	ret = hisee_hiai_key_decrypt(pdata, tmp, keylen, pdin, dinlen, tmp, &len);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handle;

	/* step3. ecc privkey verify */
	keylen = len;
	ret = hisee_hiai_key_verify(pdata, tmp, keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handle;

	/* step4. ecdh key compute */
	ret = hisee_hiai_ecdh_compute(&pdata->pubkey, tmp, keylen, pdout, doutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end_handle;

end_handle:
	(void)memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

err_bsp_t hisee_hiai_key_compute(const struct hisee_hiai_data *pdata,
				 const u8 *pdin, u32 dinlen,
				 u8 *pdout, u32 doutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hisee_hiai_key_do_compute(pdata, pdin, dinlen, pdout, doutlen)
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

