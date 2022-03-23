/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Create: 2019-11-21
 * Description: implament DRM Runtime API
 */

#ifndef CHINADRM_TEE_CHINADRM_GMSSL_API_H
#define CHINADRM_TEE_CHINADRM_GMSSL_API_H

#include <tee_defines.h>
#include "chinadrm.h"

/*
 * Use sm2 algorithm to sign input data.
 *
 * @param priv_key   [IN]  The sm2 priv key structure
 * @param input      [IN]  The input buffer to be signed
 * @param input_len  [IN]  The length of input buffer
 * @param signature  [OUT] The signature structure
 *
 * @return  TEE_SUCCESS: Sign data success
 * @return       others: Sign data failed
 */
int32_t cdrm_eps_sm2_sign(void *priv_key, uint8_t *input, uint32_t input_len, void *signature);

/*
 * Use sm2 algorithm to verify the signature.
 *
 * @param public_key [IN]  The sm2 public key structure
 * @param input      [IN]  The input buffer to be signed
 * @param input_len  [IN]  The length of input buffer
 * @param signature  [IN] The signature structure
 *
 * @return  TEE_SUCCESS: Sm2 verify success
 * @return       others: Sm2 verify failed
 */
int32_t cdrm_eps_sm2_verify(void *public_key, uint8_t *input, uint32_t input_len, void *signature);

/*
 * Use sm2 algorithm to encrypt input data.
 *
 * @param priv_key   [IN]  The sm2 priv key structure
 * @param input      [IN]  The input buffer to be encrypted
 * @param input_len  [IN]  The length of input buffer
 * @param cipher     [OUT] The cipher structure
 * @param clen       [IN]  The length of output data
 *
 * @return  TEE_SUCCESS: Encrypt data success
 * @return       others: Encrypt data failed
 */
int32_t cdrm_eps_sm2_encrypt(void *private_key, uint8_t *input, uint32_t input_len, void *cipher, uint32_t clen);

/*
 * Use sm2 algorithm to decrypt input data.
 *
 * @param public_key [IN]  The sm2 public key structure
 * @param output     [OUT] The output buffer
 * @param output_len [OUT] The length of output buffer
 * @param cipher     [IN]  The cipher structure
 * @param clen       [IN]  The length of encrypted data
 *
 * @return  TEE_SUCCESS: Decrypt data success
 * @return       others: Decrypt data failed
 */
int32_t cdrm_eps_sm2_decrypt(void *public_key, uint8_t *output, uint32_t *output_len, void *cipher, uint32_t clen);

/*
 * Do sm4 encrypt or decrypt.
 *
 * @param algorithm [IN]     The algorithm of crypto
 * @param mode      [IN]     The mode of crypto
 * @param params    [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do sm4 crypto success
 * @return       others: Do sm4 crypto failed
 */
int32_t cdrm_eps_sm4_crypto(uint32_t algorithm, uint32_t mode, struct cdrm_params *params);

/*
 * Config sm4 context.
 *
 * @param context     [OUT]    The sm4 context pointer
 * @param context_len [OUT]    The real length of sm4 context
 * @param params      [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do sm4 config success
 * @return       others: Do sm4 config failed
 */
TEE_Result cdrm_eps_sm4_config(void **context, uint32_t *context_len, struct cdrm_params *params);

/*
 * Decrypt cnec data using sm4 algorithm.
 *
 * @param context [IN]     The sm4 context
 * @param input   [IN]     The cenc encrypted data
 * @param inlen   [IN]     The length of encrypted data
 * @param output  [OUT]    The output buffer
 * @param outlen  [IN/OUT] The length of output buffer
 *
 * @return  TEE_SUCCESS: Do sm4 cenc decryption success
 * @return       others: Do sm4 cenc decryption failed
 */
TEE_Result cdrm_eps_sm4_cenc_decrypt(void *context, uint8_t *input, uint32_t inlen, uint8_t *output, uint32_t *outlen);
#endif
