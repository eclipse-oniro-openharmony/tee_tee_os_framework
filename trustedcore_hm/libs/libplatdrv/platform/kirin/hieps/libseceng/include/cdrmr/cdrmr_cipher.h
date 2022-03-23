/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cipher algorithm interface for china DRM
 * Create     : 2019/11/04
 */

#ifndef __CDRMR_CIPHER_H__
#define __CDRMR_CIPHER_H__
#include <common_utils.h>
#include <cdrmr_common.h>

#define CDRMR_CIPHER_USER_CTX_SIZE_IN_WORDS   64
struct cdrmr_cipher_user_ctx {
	u32 buff[CDRMR_CIPHER_USER_CTX_SIZE_IN_WORDS];
};

/*
 * @brief     : general symmetric encrypt
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, the length of iv
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_crypto_symmetric_encrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
				   unsigned char *pkey, unsigned int keylen,
				   unsigned char *piv, unsigned int ivlen,
				   unsigned char *pdin, unsigned int dinlen,
				   unsigned char *pdout, unsigned int *pdoutlen);

/*
 * @brief     : general symmetric decrypt
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, thelength of iv
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_crypto_symmetric_decrypt(CDRMR_Symmetric_Crypto_Algorithm algo,
				   unsigned char *pkey, unsigned int keylen,
				   unsigned char *piv, unsigned int ivlen,
				   unsigned char *pdin, unsigned int dinlen,
				   unsigned char *pdout, unsigned int *pdoutlen);

/*
 * @brief     : configure algorithm, key, iv to user context
 * @param[in] : puser_ctx, the user context
 * @param[in] : algo, algotirhm and mode
 * @param[in] : pkey, the point of key
 * @param[in] : keylen, the length of key
 * @param[in] : piv, the point of iv
 * @param[in] : ivlen, the length of iv
 * @return    : 0 if successful, others fail
 */
int cdrmr_cipher_config_handle(struct cdrmr_cipher_user_ctx *puser_ctx,
			       CDRMR_Symmetric_Crypto_Algorithm algo,
			       unsigned char *pkey, unsigned int keylen,
			       unsigned char *piv, unsigned int ivlen);

/*
 * @brief     : audio symmetric decrypt
 * @param[in] : puser_ctx, the user context
 * @param[in] : algo, algotirhm and mode, repeat with cdrmr_cipher_config_handle
 * @param[in] : pdin, the point of input data
 * @param[in] : dinlen, the length of input data
 * @param[in] : pdout, the point of output data
 * @param[in] : pdoutlen, the point of output data length
 * @return    : 0 if successful, others fail
 */
int cdrmr_cipher_cenc_decrypt(struct cdrmr_cipher_user_ctx *puser_ctx,
			      CDRMR_Cenc_Algorithm algo, unsigned char *pdin,
			      unsigned int dinlen, unsigned char *pdout,
			      unsigned int *pdoutlen);
#endif

