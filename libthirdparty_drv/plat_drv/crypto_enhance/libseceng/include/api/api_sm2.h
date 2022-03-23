/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:
 * Author     : z00293770
 * Create     : 2019/11/02
 * Note       :
 */
#ifndef __API_SM2_H__
#define __API_SM2_H__
#include <common_ecc.h>
#include <common_sce.h>

#define SM2_C1_HEAD                     (0x04)
#define SM2_C1_HEAD_LEN                 (1)
#define SM2_C1_LEN                      (SM2_POINT_LEN + SM2_C1_HEAD_LEN)
#define SM2_C3_LEN                      (SYMM_OUTLEN_SM3)
#define SM2_C_LEN(inlen)                (SM2_C1_LEN + (inlen) + SM2_C3_LEN)

enum ecc_key_e {
    ECC_KEY_PRIV  = 1, /* priv key */
    ECC_KEY_PUB   = 2, /* pub key */
    ECC_KEY_FULL  = ECC_KEY_PRIV | ECC_KEY_PUB,
};

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
err_bsp_t api_sm2_sign(struct hal_ecc_key_s *pkey,
                       u8 *pid,   u32 idlen,
                       u8 *pmsg,  u32 msglen,
                       u8 *psign, u32 *psignlen);

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
err_bsp_t api_sm2_verify(struct hal_ecc_key_s *pkey,
                         u8 *pid,   u32 idlen,
                         u8 *pmsg,  u32 msglen,
                         u8 *psign, u32 signlen);

/**
 * @brief      : sm2 encrypt, encrypto msg with pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pin, the input msg
 * @param[in]  : inlen , the msg length
 * @param[out] : pout, the cipher msg
 * @param[in]  : outlen , the out buffer length
 * @note       : encrypto msg with sm2 pubkey
 */
err_bsp_t api_sm2_encrypt(struct hal_ecc_key_s *pkey,
                          u8 *pin, u32 inlen,
                          u8 *pout, u32 *poutlen);

/**
 * @brief      : decrypto msg with sm2 privkey
 * @param[in]  : pkey, input privkey
 * @param[in]  : pin, the cipher msg
 * @param[in]  : inlen, the msg len
 * @param[out] : pout, the plain msg
 * @param[in]  : outlen , the out buffer size
 */
err_bsp_t api_sm2_decrypt(struct hal_ecc_key_s *pkey,
                          u8 *pin, u32 inlen,
                          u8 *pout, u32 *poutlen);

/**
 * @brief         : sm2 sign with privkey, input digest data(e in the spec)
 * @param[in]  : pkey, privkey
 * @param[in]  : pdigest, is hash with userid, msg , curse, pubkey
 * @param[in]  : pdigest length
 * @param[out]  : psign, the out buffer for the signature
 * @param[in/out]  : signature length
 */
err_bsp_t api_sm2_digest_sign(struct hal_ecc_key_s *pkey, u8 *pdigest, u32 digestlen, u8 *psign, u32 *psignlen);

/**
 * @brief      : verify the signature with sm2 pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pdigest, is hash with userid, msg , curse, pubkey
 * @param[in]  : pdigest length
 * @param[in]  : psign , the sigature to be verify
 * @param[in]  : signlen , the signature length
 */
err_bsp_t api_sm2_digest_verify(struct hal_ecc_key_s *pkey, u8 *pdigest, u32 digestlen, u8 *psign, u32 signlen);

/**
 * @brief      : generate sm2 keypair
 * @param[out]  : pkey, keypair
 */
err_bsp_t api_sm2_gen_keypair(struct hal_ecc_key_s *pkey);

#endif /* end of __API_SM2_H__ */
