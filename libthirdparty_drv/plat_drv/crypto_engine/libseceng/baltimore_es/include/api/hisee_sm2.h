/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: sm2 api
 * Author     : Z00358830
 * Create     : 2019/08/06
 * Note       :
 */
#ifndef __HISEE_SM2_H__
#define __HISEE_SM2_H__
#include <common_ecc.h>

/**
 * @brief      : hisee_sm2_gen_key, generate key pair
 * @param[out] : key pair
 * @note       : generate sm2 pubkey and privkey
 */
err_bsp_t hisee_sm2_gen_key(struct hisee_ecc_keypair *pkey);

/**
 * @brief      : sm2 encrypt, encrypto msg with pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pin, the input msg
 * @param[in]  : inlen , the msg length
 * @param[out] : pout, the cipher msg
 * @param[in]  : outlen , the out buffer length
 * @note       : encrypto msg with sm2 pubkey
 */
err_bsp_t hisee_sm2_encrypt(const struct hisee_ecc_pubkey *pkey,
			    const u8 *pin, u32 inlen,
			    u8 *pout, u32 *poutlen);

/**
 * @brief      : decrypto msg with sm2 privkey
 * @param[in]  : pkey, input privkey
 * @param[in]  : pin, the cipher msg
 * @param[in]  : inlen, the msg len
 * @param[out] : pout, the plain msg
 * @param[in]  : outlen , the out buffer size
 */
err_bsp_t hisee_sm2_decrypt(const struct hisee_ecc_privkey *pkey,
			    const u8 *pin, u32 inlen,
			    u8 *pout, u32 *poutlen);

/**
 * @brief      : sm2 compute za value
 * @param[in]  : pkey, pubkey
 * @param[in]  : pid, the user id
 * @param[out]  : pz, the za value
 * @param[in/out]  : pzlen, in:the buffer size of pz, out: the za length
 * @note : Z<A> = SM3(ENTL<A> || ID<A> || a || b || xG || yG || x<A> || y<A>)
 */
err_bsp_t hisee_sm2_compute_z(const struct hisee_ecc_pubkey *pkey,
			      const u8 *pid, u32 idlen,
			      const u8 *pz, u32 *pzlen);

/**
 * @brief      : sm2 compute  e value (message hash)
 * @param[in]  : pmsg, message
 * @param[in]  : pz, za value
 * @param[out] : phash, e value
 * @param[in/out]  : phashlen, in:the buffer size of phash, out: the e length
 * @note       : mhash = SM3(Z<A> ||M)
 */
err_bsp_t hisee_sm2_compute_msg_hash(const u8 *pmsg, u32 msglen,
				     const u8 *pz, u32 zlen,
				     u8 *phash, u32 *phashlen);

/**
 * @brief      : sm2 sign with privkey, input the digest of the
 * @param[in]  : pkey, privkey
 * @param[in]  : pdigest the hash value
 * @param[in]  : digest length
 * @param[out]  : psign, the out buffer for the signature
 * @param[in/out]  : signature length
 */
err_bsp_t hisee_sm2_digest_sign(const struct hisee_ecc_privkey *pkey,
				const u8 *pdigest, u32 digestlen,
				u8 *psign, u32 *psignlen);

/**
 * @brief      : sm2 sign with privkey, input userid and message
 * @param[in]  : pkey, privkey
 * @param[in]  : pid, the user id
 * @param[in]  : user id length
 * @param[in]  : pmsg, the raw data need to sign
 * @param[in]  : massage length
 * @param[out]  : psign, the out buffer for the signature
 * @param[in/out]  : signature length
 */
err_bsp_t hisee_sm2_sign(const struct hisee_ecc_keypair *pkey,
			 const u8 *pid,   u32 idlen,
			 const u8 *pmsg,  u32 msglen,
			 u8 *psign, u32 *psignlen);

/**
 * @brief      : verify the signature with sm2 pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pdigest the hash value of the msg
 * @param[in]  : digestlen , the length of the digest
 * @param[in]  : psign , the sigature to be verify
 * @param[in]  : signlen , the signature length
 * @note       : input the hash of the msg
 */
err_bsp_t hisee_sm2_digest_verify(const struct hisee_ecc_pubkey *pkey,
				  const u8 *pdigest, u32 digestlen,
				  const u8 *psign, u32 signlen);

/**
 * @brief      : verify the signature with sm2 pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pid, the user id
 * @param[in]  : user id length
 * @param[in]  : pmsg, the raw data of the sign
 * @param[in]  : massage length
 * @param[in]  : psign , the sigature to be verify
 * @param[in]  : signlen , the signature length
 * @note       : input the hash of the msg
 */
err_bsp_t hisee_sm2_verify(const struct hisee_ecc_pubkey *pkey,
			   const u8 *pid, u32 idlen,
			   const u8 *pmsg, u32 msglen,
			   const u8 *psign, u32 signlen);

#endif /* end of __HISEE_SM2_H__ */
