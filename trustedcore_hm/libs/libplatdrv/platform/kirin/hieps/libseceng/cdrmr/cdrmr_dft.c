/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: test algorithm interface for china DRM2.0
 * Author     : z00293770
 * Create     : 2019/11/02
 */
#include <cdrmr_sm2.h>
#include <cdrmr_common.h>
#include <api_sm2.h>
#include <pal_libc.h>
#include <api_utils.h>

#define BSP_THIS_MODULE         BSP_MODULE_ECC

/* C1 header:1byte, C1 len:64byte, C3 len:32byte */
#define SM2_ENC_INCREASE_LEN    (1 + 64 + 32)

/**
 * @brief     : SM2 encrypto with sm2 pubkey
 * @param[in] : ecc pubkey, refer to GB/T 36322-2018
 * @param[in] : pin, the plain msg
 * @param[in] : inlen, the plain msg length
 * @param[out]: pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int test_cdrmr_cipher_sm2_encrypt(ECCrefPublicKey *ppubkey,
				  unsigned char *pin, unsigned int inlen,
				  unsigned int enclen, ECCCipher *pcipher)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!pcipher, ERR_API(ERRCODE_NULL));
	pcipher->L = enclen;

	ret = cdrmr_cipher_sm2_encrypt(ppubkey, pin, inlen, pcipher);

	return ret;
}

/**
 * @brief     : SM2 decrypto msg with sm2 privkey
 * @param[in] : ecc pprivkey, refer to GB/T 36322-2018
 * @param[out]: pout, the plain msg
 * @param[out]: outlen , the out buffer size
 * @param[in] : pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int test_cdrmr_cipher_sm2_decrypt(ECCrefPrivateKey *pprivkey,
				  unsigned char *pout, unsigned int *poutlen,
				  unsigned int enclen, ECCCipher *pcipher)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!pcipher, ERR_API(ERRCODE_NULL));
	pcipher->L = enclen;

	ret = cdrmr_cipher_sm2_decrypt(pprivkey, pout, poutlen, pcipher);

	return ret;
}

