/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: declare of sm2 api
 * Create     : 2019/11/02
 */

#ifndef __CDRMR_SM2_H__
#define __CDRMR_SM2_H__
#include <cdrmr_common.h>

/*
 * @brief     : SM2 signature with sm2 privkey
 * @param[in] : ecc priv key, refer to GB/T 36322-2018
 * @param[in] : pin, the msg
 * @param[in] : inlen, the msg length
 * @param[in] : psign, the signature data, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_sign(ECCrefPrivateKey *pprivkey,
			  unsigned char *pin, unsigned int inlen,
			  ECCSignature *psign);

/*
 * @brief     : SM2 verify signature with sm2 pubkey
 * @param[in] : ecc pubkey, refer to GB/T 36322-2018
 * @param[in] : pin, the msg
 * @param[in] : inlen, the msg length
 * @param[in] : psign, the signature data, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_verify(ECCrefPublicKey *ppubkey,
			    unsigned char *pin, unsigned int inlen,
			    ECCSignature *psign);

/*
 * @brief     : SM2 encrypto with sm2 pubkey
 * @param[in] : ecc pubkey, refer to GB/T 36322-2018
 * @param[in] : pin, the plain msg
 * @param[in] : inlen, the plain msg length
 * @param[out]: pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_encrypt(ECCrefPublicKey *ppubkey,
			     unsigned char *pin, unsigned int inlen,
			     ECCCipher *pcipher);

/*
 * @brief     : SM2 decrypto msg with sm2 privkey
 * @param[in] : ecc pprivkey, refer to GB/T 36322-2018
 * @param[out]: pout, the plain msg
 * @param[out]: outlen , the out buffer size
 * @param[in] : pcipher, the cipher msg, refer to GB/T 36322-2018
 */
int cdrmr_cipher_sm2_decrypt(ECCrefPrivateKey *pprivkey,
			     unsigned char *pout, unsigned int *poutlen,
			     ECCCipher *pcipher);

#endif /* end of __CDRMR_SM2_H__ */

