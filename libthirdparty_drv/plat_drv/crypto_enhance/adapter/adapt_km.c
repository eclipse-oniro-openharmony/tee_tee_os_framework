/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description  : add km api, parallel with DX api, called by GP
 * Author       : l00370476, liuchong13@huawei.com
 * Create       : 2018/12/27
 */
#include <adapt_km.h>
#include <api_km.h>
#include "adapt_rsa.h"
#include "adapt_common.h"
#include <pal_libc.h>
#include <pal_log.h>
#include <sec_utils.h>

CCError_t EPS_EncryptClientPrivK(EPSEncPrivK_t *pprivk)
{
	err_bsp_t ret;

	ret = api_encrypt_client_privk(pprivk);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

CCError_t EPS_DecryptLicenceHmacK(CCRsaUserPrivKey_t *pkey, u8 *pdin, u32 dinlen,
				  u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret;
	CCRsaPrivKey_t *priv_key_ptr = NULL;
	hal_rsa_key_s tmp_key = {0};

	if (!pkey)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	if (pkey->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	priv_key_ptr = (CCRsaPrivKey_t *)pkey->PrivateKeyDbBuff;

	tmp_key.width = priv_key_ptr->nSizeInBits;
	tmp_key.pn    = (u8 *)priv_key_ptr->n;
	tmp_key.pd    = (u8 *)priv_key_ptr->PriveKeyDb.NonCrt.d;

	/* convert Key from little endian to big endian */
	ret = sec_convert_little_to_big_endian(tmp_key.pn, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       tmp_key.pn, BIT2BYTE(tmp_key.width));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian(tmp_key.pd, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE, tmp_key.pd,
					       BIT2BYTE(priv_key_ptr->PriveKeyDb.NonCrt.dSizeInBits));
	PAL_ERR_RETURN(ret);

	ret = api_decrypt_licence_hmack(&tmp_key, pdin, dinlen, pdout, pdoutlen);

	(void)memset_s(&tmp_key, sizeof(tmp_key), 0, sizeof(tmp_key));

	return CONVERT_RET_AGENT2ADAPT(ret);
}

CCError_t EPS_DecryptSessionKey(CCRsaUserPrivKey_t *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret;
	CCRsaPrivKey_t *priv_key_ptr = NULL;
	hal_rsa_key_s ptmpkey = {0};

	if (!pkey)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	if (pkey->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	priv_key_ptr = (CCRsaPrivKey_t *)pkey->PrivateKeyDbBuff;

	ptmpkey.width = priv_key_ptr->nSizeInBits;
	ptmpkey.pn    = (u8 *)priv_key_ptr->n;
	ptmpkey.pd    = (u8 *)priv_key_ptr->PriveKeyDb.NonCrt.d;

	/* convert Key from little endian to big endian */
	ret = sec_convert_little_to_big_endian(ptmpkey.pn, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       ptmpkey.pn, BIT2BYTE(ptmpkey.width));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian(ptmpkey.pd, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE, ptmpkey.pd,
					       BIT2BYTE(priv_key_ptr->PriveKeyDb.NonCrt.dSizeInBits));
	PAL_ERR_RETURN(ret);

	ret = api_decrypt_session_key(&ptmpkey, pdin, dinlen, pdout, pdoutlen);

	(void)memset_s(&ptmpkey, sizeof(ptmpkey), 0, sizeof(ptmpkey));
	return CONVERT_RET_AGENT2ADAPT(ret);
}

CCError_t EPS_DecryptCek(u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret;

	ret = api_decrypt_cek(pdin, dinlen, pdout, pdoutlen);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

