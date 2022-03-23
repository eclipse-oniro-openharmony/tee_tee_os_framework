/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: sm2 algorithm interface for china DRM2.0
 * Author     : z00293770
 * Create     : 2019/11/02
 */
#include <cdrmr_sm2.h>
#include <cdrmr_common.h>
#include <api_sm2.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE BSP_MODULE_ECC

#define USER_ID_LEN 16

u8 g_user_id[USER_ID_LEN] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

/**
 * @brief     : SM2 signature with sm2 privkey
 * @param[in] : ecc priv key, refer to GB/T 36322-2018
 * @param[in] : pin, the msg
 * @param[in] : inlen, the msg length
 * @param[in] : psign, the signature data, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_sign(ECCrefPrivateKey *pprivkey,
			  unsigned char *pin, unsigned int inlen,
			  ECCSignature *psign)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	struct hal_ecc_key_s key = {0};
	u32 key_len = SM2_KEY_LEN;
	u32 signlen = SM2_POINT_LEN;

	PAL_CHECK_RETURN(!pprivkey, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psign, ERR_API(ERRCODE_NULL));

	key.width = pprivkey->bits;
	key.ppriv = pprivkey->K;
	key.ppubx = pprivkey->x;
	key.ppuby = pprivkey->y;

	ret = api_sm2_sign(&key, g_user_id, USER_ID_LEN,
			   pin, inlen, psign->r, &signlen);
	PAL_ERR_RETURN(ret);

	libc_ret = memcpy_s(psign->s, sizeof(psign->s),
			    &psign->r[key_len], key_len);
	PAL_CHECK_RETURN(libc_ret != EOK, ERR_API(ERRCODE_MEMORY));
	(void)memset_s(&psign->r[key_len], key_len, 0, key_len);

	return CDRMR_OK;
}

/**
 * @brief     : SM2 verify signature with sm2 pubkey
 * @param[in] : ecc pubkey, refer to GB/T 36322-2018
 * @param[in] : pin, the msg
 * @param[in] : inlen, the msg length
 * @param[in] : psign, the signature data, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_verify(ECCrefPublicKey *ppubkey,
			    unsigned char *pin, unsigned int inlen,
			    ECCSignature *psign)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	struct hal_ecc_key_s key = {0};
	u32 key_len = SM2_KEY_LEN;
	u32 signlen = SM2_POINT_LEN;

	PAL_CHECK_RETURN(!ppubkey, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psign, ERR_API(ERRCODE_NULL));

	key.width = ppubkey->bits;
	key.ppriv = NULL;
	key.ppubx = ppubkey->x;
	key.ppuby = ppubkey->y;

	libc_ret = memcpy_s(&psign->r[key_len], sizeof(psign->r) - key_len,
			    psign->s, key_len);
	PAL_CHECK_RETURN(libc_ret != EOK, ERR_API(ERRCODE_MEMORY));

	ret = api_sm2_verify(&key, g_user_id, USER_ID_LEN, pin, inlen,
			     psign->r, signlen);
	PAL_ERR_RETURN(ret);

	(void)memset_s(&psign->r[key_len], key_len, 0, key_len);

	return CDRMR_OK;
}

/**
 * @brief     : SM2 encrypto with sm2 pubkey
 * @param[in] : ecc pubkey, refer to GB/T 36322-2018
 * @param[in] : pin, the plain msg
 * @param[in] : inlen, the plain msg length
 * @param[out]: pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_encrypt(ECCrefPublicKey *ppubkey,
			     unsigned char *pin, unsigned int inlen,
			     ECCCipher *pcipher)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hal_ecc_key_s key = {0};
	errno_t libc_ret = EINVAL;
	u32 key_len = SM2_KEY_LEN;

	PAL_CHECK_RETURN(!ppubkey, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pcipher, ERR_API(ERRCODE_NULL));

	key.width = ppubkey->bits;
	key.ppriv = NULL;
	key.ppubx = ppubkey->x;
	key.ppuby = ppubkey->y;

	ret = api_sm2_encrypt(&key, pin, inlen, pcipher->C, &pcipher->L);
	PAL_ERR_RETURN(ret);

	libc_ret = memcpy_s(pcipher->x, sizeof(pcipher->x), ppubkey->x, key_len);
	PAL_CHECK_RETURN(libc_ret != EOK, ERR_API(ERRCODE_MEMORY));

	libc_ret = memcpy_s(pcipher->y, sizeof(pcipher->y), ppubkey->y, key_len);
	PAL_CHECK_RETURN(libc_ret != EOK, ERR_API(ERRCODE_MEMORY));

	return CDRMR_OK;
}

/**
 * @brief     : SM2 decrypto msg with sm2 privkey
 * @param[in] : ecc pprivkey, refer to GB/T 36322-2018
 * @param[out]: pout, the plain msg
 * @param[out]: outlen , the out buffer size
 * @param[in] : pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_decrypt(ECCrefPrivateKey *pprivkey,
			     unsigned char *pout, unsigned int *poutlen,
			     ECCCipher *pcipher)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hal_ecc_key_s key = {0};

	PAL_CHECK_RETURN(!pprivkey, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pcipher, ERR_API(ERRCODE_NULL));

	key.width = pprivkey->bits;
	key.ppriv = pprivkey->K;
	key.ppubx = NULL;
	key.ppuby = NULL;

	ret = api_sm2_decrypt(&key, pcipher->C, pcipher->L, pout, poutlen);
	PAL_ERR_RETURN(ret);

	return CDRMR_OK;
}

