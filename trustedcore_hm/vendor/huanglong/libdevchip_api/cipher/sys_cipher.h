/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee cipher head file
 * Author: cipher group
 * Create: 2019-12-11
 */

#ifndef __SYS_CIPHER_H__
#define __SYS_CIPHER_H__

#include "user_osal_lib.h"

#ifdef __cplusplus
extern "C" {
#endif    /* __cplusplus */

/******************************* API Declaration *****************************/
/** \addtogroup      mpi */
/** @{ */  /** <!--[mpi] */

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      crypto */
/** @{ */  /** <!-- [link] */

/**
\brief   mpi Init.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_init(hi_void);

/**
\brief   Kapi Deinit.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_deinit(hi_void);

/**
\brief   Create symc handle.
\param[in]  id The channel number.
\param[in]  uuid The user identification.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_create(hi_u32 *id, hi_cipher_type type);

/**
\brief   Destroy symc handle.
\param[in]  id The channel number.
\param[in]  uuid The user identification.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_destroy(hi_u32 id);

/**
\brief   get keyslot handle.
\param[in]  cipher The cipher handle.
\param[out]  keyslot The keyslot handle.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_get_keyslot_handle(hi_handle cipher,  hi_handle *keyslot);

/**
\brief  set work params.
* \param[in]  id            The channel number.
* \param[in]  hard_key      whether use the hard key or not.
* \param[in]  alg         The symmetric cipher algorithm.
* \param[in]  work_mode    The symmetric cipher mode.
* \param[in]  bit_width    The symmetric cipher bit width.
* \param[in]  key_len      The symmetric cipher key len.
* \param[in]  sm1_round_num The round number of sm1.
* \param[in]  fkey          first key buffer, defualt
* \param[in]  skey          second key buffer, expand
* \param[in]  keylen        The length of fkey buffer,if skey is not null,equal to the length of skey.
* \param[in]  iv            iv buffer.
* \param[in]  ivlen         The length of iv buffer.
* \param[in]  iv_usage      iv change.
* \param[in]  aad           Associated Data
* \param[in]  alen          Associated Data Length
* \param[in]  tlen          Tag length
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_config(hi_u32 id,
                       hi_cipher_alg alg,
                       hi_cipher_work_mode work_mode,
                       hi_cipher_bit_width bit_width,
                       hi_cipher_key_length key_len,
                       const hi_u8 *iv, hi_u32 ivlen, hi_u32 iv_usage,
                       hi_mem_handle aad, hi_u32 alen, hi_u32 tlen);

/**
\brief  get work params.
* \param[in]  id The channel number.
* \param[out] ctrl infomation.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_symc_get_config(hi_u32 id, hi_cipher_ctrl *ctrl);

/**
 * \brief          SYMC  buffer encryption/decryption.
 *
 * Note: Due to the nature of aes you should use the same key schedule for
 * both encryption and decryption.
 *
 * \param[in]  id The channel number.
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 * \param length   length of the input data
 * \param decrypt  decrypt or encrypt
 *
 * \return         0 if successful
 */
hi_s32 sys_symc_crypto(hi_u32 id, hi_mem_handle input,
                       hi_mem_handle output, hi_u32 length,
                       hi_u32 operation,
                       hi_tee_cipher_data_dir data_dir);

/**
 * \brief          SYMC multiple buffer encryption/decryption.
 *
 * Note: Due to the nature of aes you should use the same key schedule for
 * both encryption and decryption.
 *
 * \param[in]  id The channel number.
 * \param pkg       Buffer of package infomation
 * \param pkg_num   Number of package infomation
 * \param decrypt  decrypt or encrypt
 *
 * \return         0 if successful
 */
hi_s32 sys_symc_crypto_multi(hi_u32 id, const hi_cipher_data *pkg,
                             hi_u32 pkg_num, hi_u32 operation,
                             hi_tee_cipher_data_dir data_dir);

/**
 * \brief          SYMC multiple buffer encryption/decryption.
 *
 * Note: Due to the nature of aes you should use the same key schedule for
 * both encryption and decryption.
 *
 * \param[in]  id The channel number.
 * \param in      Buffer of input
 * \param inlen   Length of input
 * \param mac     CMAC
 * \param last    last or not
 *
 * \return         0 if successful
 */
hi_s32 sys_symc_aes_cmac(hi_u32 id, hi_u8 *in, hi_u32 inlen, hi_u8 *mac, hi_u32 last);

/**
 * \brief          SYMC multiple buffer encryption/decryption.
 * \param[in]  id The channel number.
 * \param[in]  tag tag data of CCM/GCM
 * \param uuid uuid The user identification.
 *
 * \return         0 if successful
 */
hi_s32 sys_aead_get_tag(hi_u32 id, hi_u8 *tag, hi_u32 *taglen);

/**
\brief   Kapi Init.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_hash_init(hi_void);

/**
\brief   Kapi Deinit.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_hash_deinit(hi_void);

/**
 * \brief          HASH context setup.
 *
 *
 * \param[out] id The channel number.
 * \param[in] type    Hash type
 * \param[in] key     hmac key
 * \param[in] keylen  hmac key length
 *
 * \return         0 if successful
 */
hi_s32 sys_hash_start(hi_u32 *id, hi_cipher_hash_type type,
                      const hi_u8 *key, hi_u32 keylen);

/**
 * \brief          HASH process buffer.
 *
 * \param[in]  id The channel number.
 * \param[in] input    buffer holding the input data
 * \param[in] length   length of the input data
 * \param[in] src      source of hash message
 *
 * \return         0 if successful
 */
hi_s32 sys_hash_update(hi_u32 id, const hi_u8 *input, hi_u32 length,
                       hash_chunk_src src);

/**
 * \brief          HASH final digest.
 *
 * \param[in]  id The channel number.
 * \param[out] hash    buffer holding the hash data
 * \param[out] hashlen length of the hash data
 * \param[in] uuid uuid The user identification.
 *
 * \return         0 if successful
 */
hi_s32 sys_hash_finish(hi_u32 id, hi_u8 *hash, hi_u32 *hashlen);

/**
\brief   Kapi Init.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_rsa_init(hi_void);

/**
\brief   Kapi Deinitialize.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_rsa_deinit(hi_void);

/**
* \brief RSA encryption a plaintext with a RSA private key.
*
* \param[in] key:       rsa key struct.
* \param[in] scheme:  rsa encrypt/decrypt scheme.
* \param[in] in   input data to be encryption
* \param[out] inlen:  length of input data to be encryption
* \param[out] out   output data of encryption
* \param[out] outlen: length of output data to be encryption
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_encrypt(const cryp_rsa_key *key,
                       hi_cipher_rsa_enc_scheme scheme,
                       const hi_u8 *in, hi_u32 inlen, hi_u8 *out, hi_u32 *outlen);

/**
* \brief RSA decryption a ciphertext with a RSA public key.
*
* \param[in] key:       rsa key struct.
* \param[in] scheme:  rsa encrypt/decrypt scheme.
* \param[in] in   input data to be encryption
* \param[in] inlen:  length of input data to be encryption
* \param[out] out   output data to be encryption
* \param[out] outlen: length of output data to be encryption
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_decrypt(const cryp_rsa_key *key,
                       hi_cipher_rsa_enc_scheme scheme,
                       const hi_u8 *in, hi_u32 inlen, hi_u8 *out, hi_u32 *outlen);

/**
* \brief RSA signature a context with appendix, where a signers RSA private key is used.
*
* \param[in] key:       rsa key struct.
* \param[in] scheme:  rsa signature/verify scheme.
* \param[in] in    input data to be encryption
* \param[in] inlen:  length of input data to be encryption
* \param[in] hash:   hash value of context,if NULL, let hash = Hash(context) automatically
* \param[out] out   output data to be encryption
* \param[out] outlen: length of output data to be encryption
* \param[in]  src      source of hash message
* \param[in]  uuid uuid The user identification.
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_sign_hash(const cryp_rsa_key *key,
                         hi_cipher_rsa_sign_scheme scheme,
                         const hi_u8 *hash, hi_u32 hlen, hi_u8 *sign, hi_u32 *signlen);

/**
* \brief RSA verify a ciphertext with a RSA public key.
*
* \param[in]  key_info:   encryption struct.
* \param[in]  in   input data to be encryption
* \param[out] inlen:  length of input data to be encryption
* \param[in]  hash:   hash value of context,if NULL, let hash = Hash(context) automatically
* \param[out] out   output data to be encryption
* \param[out] outlen: length of output data to be encryption
* \param[in]  src      source of hash message
* \param[in]  uuid uuid The user identification.
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_verify_hash(const cryp_rsa_key *key,
                           hi_cipher_rsa_sign_scheme scheme,
                           const hi_u8 *hash, hi_u32 hlen, const hi_u8 *sign, hi_u32 signlen);

/**
* \brief Generate a RSA private key.
*
* \param[in]  key:   rsa key struct.
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_gen_key(cryp_rsa_key *key);

/**
* \brief Compute Diffie-Hellman shared secret as otherPubKey^privKey mod p.
*
* \param[in]  key:   rsa key struct.
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_rsa_compute_ctr(cryp_rsa_key *key);

/**
* \brief klad call this function to set iv.
*
* \param[in]  hCIHandle:   handle.
* \param[in]  iv   iv data
* \param[in]  inlen:  length of input data to be encryption
* \retval HI_SUCCESS  Call this API successful
* \retval HI_FAILURE  Call this API fails.
*/
hi_s32 sys_symc_setiv(hi_u32 handle, hi_u8 *iv, hi_u32 ivlen);

/**
\brief get rand number.
\param[out]  randnum rand number.
\param[in]   size size of rand number.
\param[in]   timeout time out.
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_trng_get_random(hi_u8 *randnum, hi_u32 size, hi_u32 timeout);

/**
\brief SM2 signature a context with appendix, where a signers SM2 private key is used.
\param d[in]     sm2 private key
\param px[in]    sm2 x public key
\param py[in]    sm2 y public key
\param id[in]    sm2 user id
\param idlen[in] length of sm2 user id
\param msg[in]   mesaage to be sign
\param msglen[in] length of mesaage to be sign
\param src[in]    source of hash message
\param r[out]      sm2 sign result of r
\param s[out]      sm2 sign result of s
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_sm2_sign(const hi_u32 d[SM2_LEN_IN_WROD],
                    const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                    const hi_u8 *id, hi_u16 idlen,
                    const hi_u8 *msg, hi_u32 msglen, hash_chunk_src src,
                    hi_u8 r[SM2_LEN_IN_BYTE], hi_u8 s[SM2_LEN_IN_BYTE]);
/**
\brief SM2 signature verification a context with appendix, where a signers SM2 public key is used.
\param px[in]    sm2 x public key
\param py[in]    sm2 y public key
\param id[in]    sm2 user id
\param idlen[in] length of sm2 user id
\param msg[in]   mesaage to be sign
\param msglen[in] length of mesaage to be sign
\param src[in]    source of hash message
\param r[in]      sm2 sign result of r
\param s[in]      sm2 sign result of s
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_sm2_verify(const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                      const hi_u8 *id, hi_u16 idlen, const hi_u8 *msg, hi_u32 msglen, hash_chunk_src src,
                      const hi_u8 r[SM2_LEN_IN_BYTE], const hi_u8 s[SM2_LEN_IN_BYTE]);

/**
\brief SM2 encryption a plaintext with a RSA public key.
\param px[in]    sm2 x public key
\param py[in]    sm2 y public key
\param msg[in]   mesaage to be encryption
\param msglen[in] length of mesaage to be encryption
\param enc[out]    encryption mesaage
\param enclen[out] length of encryption mesaage
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_sm2_encrypt(const hi_u32 px[SM2_LEN_IN_WROD], const hi_u32 py[SM2_LEN_IN_WROD],
                       const hi_u8 *msg, hi_u32 msglen, hi_u8 *enc, hi_u32 *enclen);
/**
\brief SM2 decryption a plaintext with a RSA public key.
\param d[in]     sm2 private key
\param enc[out]    mesaage to be decryption
\param enclen[out] length of mesaage to be decryption
\param msg[in]     decryption mesaage
\param msglen[in]  length of decryption mesaage
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_sm2_decrypt(const hi_u32 d[SM2_LEN_IN_WROD], const hi_u8 *enc,
                       hi_u32 enclen, const hi_u8 *msg, hi_u32 *msglen);

/**
\brief Generate a SM2 key pair..
\param d[in]     sm2 private key
\param px[in]    sm2 x public key
\param py[in]    sm2 y public key
\retval     On success, HI_SUCCESS is returned.  On error, HI_FAILURE is returned.
*/
hi_s32 sys_sm2_gen_key(hi_u32 d[SM2_LEN_IN_WROD],
                       hi_u32 px[SM2_LEN_IN_WROD], hi_u32 py[SM2_LEN_IN_WROD]);

/**
\brief CENC decryption a ciphertext.
\param id[in] Cipher handle
\param key[in] for cipher decryption
\param iv[in] for cipher decryption
\param inphy[in] non-secure Physical address of the source data
\param outphy[in] secure Physical address of the target data
\param length[in] Length of the decrypted data
\param firstoffset[in] offset of the first encrypt block data
\retval HI_SUCCESS  Call this API succussful.
\retval HI_FAILURE  Call this API fails.
\see \n
N/A
*/
hi_s32 sys_cenc_decrypt(hi_handle handle, const hi_cipher_cenc *cenc,
                        hi_mem_handle inphy, hi_mem_handle outphy,
                        hi_u32 length);

/** @} */  /** <!-- ==== API Code end ==== */

#ifdef __cplusplus
}
#endif    /* __cplusplus */

#endif    /* End of #ifndef __SYS_CIPHER_H__ */
