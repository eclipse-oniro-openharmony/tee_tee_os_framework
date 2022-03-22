/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sm9 interface
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */

#ifndef __HISEE_SM9_H__
#define __HISEE_SM9_H__
#include <common_define.h>

enum hisee_sm9_en {
	SM9_ENCRYPT_WITH_SM3_XOR,
	SM9_ENCRYPT_WITH_SM3_SM4_CBC_NOPADDING,
	SM9_ENCRYPT_WITH_SM3_SM4_CTR,
	SM9_ENCRYPT_WITH_SM3_SM4_CBC_ISO9797_M1,
	SM9_ENCRYPT_WITH_SM3_SM4_CBC_ISO9797_M2,
	SM9_ENCRYPT_WITH_SM3_SM4_CBC_PKCS7,
	SM9_ENCRYPT_WITH_MAX
};

enum sm9_scheme {
	SM9_SIGN,
	SM9_ENCRYPT,
	SM9_KEY_AGREEMENT
};

struct hisee_sm9_public_key {
	u32 pairing;                  /* sm9 curve id support enum ecc_curve_id */
	struct basic_data *ppub;      /* master public key */
	struct basic_data *ppre_data; /* precompute g=e(Ppub-e, P2) or g = e(P1, Ppub-s) */
};

struct hisee_sm9_user_private_key {
	struct basic_data *puser_key; /* user private key */
};

struct hisee_sm9_en_para {
	u32 sm9_en_type;       /* encrypt type support enum hisee_sm9_en */
	struct basic_data *iv; /* iv valid when en_type is block cipher */
};

struct hisee_sm9_master_key {
	u32 pairing; /* sm9 curve id support enum ecc_curve_id */
	u32 scheme;  /* key type support enum sm9_scheme */
	u32 hash;    /* support enum symm_alg, only SYMM_ALGORITHM_SM3 */
	struct basic_data  *ppoint_pub;     /* master public key */
	struct basic_data  *pmaster_secret; /* master private key */
};

/**
 * @brief      : sm9 standard prim sign
 * @param[in]  : hash_type , support enum symm_alg, only SYMM_ALGORITHM_SM3
 * @param[in]  : psk , user sign private key
 * @param[in]  : pmpk , master public key and curve id
 * @param[in]  : pdata , data to be signed
 * @param[in]  : datalen , data length to be signed
 * @param[out]  : psig, signed result (h, s)
 * @param[in/out]  : psiglen, signed result length
 */
err_bsp_t hisee_sm9_sign(u32 hash_type, const struct hisee_sm9_user_private_key *psk,
			 const struct hisee_sm9_public_key *pmpk, const u8 *pdata, u32 datalen,
			 u8 *psig, u32 *psiglen);

/**
 * @brief      : sm9 standard prim verify
 * @param[in]  : hash_type , support enum symm_alg, only SYMM_ALGORITHM_SM3
 * @param[in]  : pmpk master public key and curve id
 * @param[in]  : pid the other id
 * @param[in]  : pdata data to be verified
 * @param[in]  : datalen data length to be verified
 * @param[in]  : psig signature
 * @param[in]  : siglen signature len
 */
err_bsp_t hisee_sm9_verify(u32 hash_type, const struct hisee_sm9_public_key *pmpk,
			   const struct basic_data *pid,
			   const u8 *pdata, u32 datalen,
			   const u8 *psig, u32 siglen);

/**
 * @brief      : sm9 standard prim encrypt
 * @param[in]  : pen_type include encrypt type and iv
 * @param[in]  : pmpk master public key and curve id
 * @param[in]  : pid  the other id
 * @param[in]  : pin data to be encrypted
 * @param[in]  : inlen data length to be encrypted
 * @param[out]  : pout encrypt result C=C1||C3||C2 in and out addr not support cross
 * @param[in/out]  : poutlen encrypt result length
 */
err_bsp_t hisee_sm9_encrypt(const struct hisee_sm9_en_para *pen_type, const struct hisee_sm9_public_key *pmpk,
			    const struct basic_data *pid, const u8 *pin, u32 inlen, u8 *pout, u32 *poutlen);

/**
 * @brief      : sm9 standard prim decrypt
 * @param[in]  : pen_type include encrypt type and iv
 * @param[in]  : psk user private encrypt key
 * @param[in]  : curve_id enum ecc_curve_id on support CURVE_ID_SM9BN256V1
 * @param[in]  : pid  the user self id
 * @param[in]  : pin data to be decrypted
 * @param[in]  : inlen data length to be decrypted
 * @param[out]  : pout decrypt result M in and out addr not support cross
 * @param[in/out]  : poutlen decrypt result length
 */
err_bsp_t hisee_sm9_decrypt(const struct hisee_sm9_en_para *pen_type,
			    const struct hisee_sm9_user_private_key *psk, u32 curve_id, const struct basic_data *pid,
			    const u8 *pin, u32 inlen, u8 *pout, u32 *poutlen);

/**
 * @brief      : sm9 standard prim wrap key
 * @param[in]  : hash_type support enum symm_alg, only SYMM_ALGORITHM_SM3
 * @param[in]  : pmpk master public key and curve id
 * @param[in]  : pid the other id
 * @param[out]  : pkey wrap key
 * @param[in]  : keylen wrap key len
 * @param[out]  : penced_key encrypted C
 * @param[in/out]  : penced_len encrypted C length
 */
err_bsp_t hisee_sm9_wrap_key(u32 hash_type, const struct hisee_sm9_public_key *pmpk,
			     const struct basic_data *pid, u8 *pkey, u32 keylen, u8 *penced_key, u32 *penced_len);

/**
 * @brief      : sm9 standard prim unwrap key
 * @param[in]  : hash_type support enum symm_alg, only SYMM_ALGORITHM_SM3
 * @param[in]  : psk user private encrypt key
 * @param[in]  : curve_id enum ecc_curve_id on support CURVE_ID_SM9BN256V1
 * @param[in]  : pid the user self id
 * @param[out]  : pkey wrap key
 * @param[in]  : keylen wrap key len
 * @param[in]  : penced_key encrypted C
 * @param[in]  : enced_len encrypted C length
 * @note       :
 */
err_bsp_t hisee_sm9_unwrap_key(u32 hash_type, const struct hisee_sm9_user_private_key *psk, u32 curve_id,
			       const struct basic_data *pid, u8 *pkey, u32 keylen, const u8 *penced_key, u32 enced_len);

/**
 * @brief      : KGC gen master key pairs
 * @param[in]  : pairing enum ecc_curve_id on support CURVE_ID_SM9BN256V1
 * @param[in]  : scheme key type support enum sm9_scheme
 * @param[in]  : hash support enum symm_alg, only SYMM_ALGORITHM_SM3
 * @param[in/out]  : pmpk key pair
 */
err_bsp_t hisee_sm9_generate_master_key(u32 pairing, u32 scheme, u32 hash, struct hisee_sm9_master_key *pmpk);

/**
 * @brief      : KGC gen user private key
 * @param[in]  : pmaster master key pair
 * @param[in]  : pid the user self id
 * @param[in/out]  : pk user private key
 */
err_bsp_t hisee_sm9_extract_private_key(const struct hisee_sm9_master_key *pmaster, const struct basic_data *pid,
					struct basic_data *pk);

/**
 * @brief      : precompute pre_data out buffer must  greate 768 bytes
 *             :            g = e(Ppub-e, P2)
 *             :            g = e(P1, Ppub-s)
 */
err_bsp_t hisee_sm9_precompute_data(u32 curve_id, const struct basic_data *pupbs, const struct basic_data *pupbe,
				    struct basic_data *pre_data);

#endif /* end of __HISEE_SM9_H__ */
