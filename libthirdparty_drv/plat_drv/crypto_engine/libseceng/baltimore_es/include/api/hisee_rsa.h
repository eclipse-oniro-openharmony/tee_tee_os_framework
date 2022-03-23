/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: rsa api
 * Author     : Z00358830
 * Create     : 2019/08/06
 * Note       : the rsa api
 */
#ifndef __HISEE_RSA_H__
#define __HISEE_RSA_H__

#include <common_rsa.h>
#include <common_pke.h>

#ifndef RSA_MAKEUP
#define RSA_MAKEUP(pad_mode, mfg_algo, hash_algo, cipher_mode) \
		((((u32)(pad_mode) & 0xFF) << 24) | \
		(((mfg_algo) & 0xFF) << 16) | \
		(((hash_algo) & 0xFF) << 8) | \
		((cipher_mode) & 0xFF))

#define RSA_GET_PAD_MODE(algo)       (((algo) >> 24) & 0xFF)

#define RSA_GET_MGF_ALGO(algo)      (((algo) >> 16) & 0xFF)

#define RSA_GET_HASH_ALGO(algo)      (((algo) >> 8) & 0xFF)

#define RSA_GET_CIPHER_MODE(algo)    ((algo) & 0xFF)
#endif

#define RSA_RESERVE       0

enum rsa_pad_mode {
	RSA_NOPAD         = 1,
	RSAES_PKCS1_V1_5  = 2,
	RSAES_PKCS1_OAEP  = 3,
	RSASSA_PKCS1_V1_5 = 4,
	RSASSA_PKCS1_PSS  = 5,
};

enum rsa_mgf_algo {
	MGF_V1            = 1,
};

enum rsa_hash_algo {
	HASH_SHA1         = 1,
	HASH_SHA224       = 2,
	HASH_SHA256       = 3,
	HASH_SHA384       = 4,
	HASH_SHA512       = 5,
};

enum rsa_cipher_mode {
	RSA_CRYPT           = 1,
	RSA_SIGN            = 2,
};

/*
 *  hisee_rsa_algorithm:  |    1 byte  |   2 byte    |   3 byte   |    4 byte
 *                        |  pad mode  |  mfg algo   |  hash algo |  sign or crypt
 * pad mode:   01:NOPAD,               02:RSAES_PKCS1_V1_5,    03:RSAES_PKCS1_OAEP
 *             04:RSASSA_PKCS1_V1_5    05:RSASSA_PKCS1_PSS
 * mfg algo:   01:MFG_ALGO_V1
 * hash algo:  01:SHA1                 02:SHA224              03:SHA256
 *             04:SHA384               05:SHA512
 * sign/crypt: 01:RSA CRYPT            02:RSA SIGN
 */
enum hisee_rsa_algorithm {
	HISEE_ALG_RSA_NOPAD                    = RSA_MAKEUP(RSA_NOPAD, RSA_RESERVE, RSA_RESERVE, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_V1_5             = RSA_MAKEUP(RSAES_PKCS1_V1_5, RSA_RESERVE, RSA_RESERVE, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1   = RSA_MAKEUP(RSAES_PKCS1_OAEP, MGF_V1, HASH_SHA1, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 = RSA_MAKEUP(RSAES_PKCS1_OAEP, MGF_V1, HASH_SHA224, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 = RSA_MAKEUP(RSAES_PKCS1_OAEP, MGF_V1, HASH_SHA256, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 = RSA_MAKEUP(RSAES_PKCS1_OAEP, MGF_V1, HASH_SHA384, RSA_CRYPT),
	HISEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 = RSA_MAKEUP(RSAES_PKCS1_OAEP, MGF_V1, HASH_SHA512, RSA_CRYPT),
	HISEE_ALG_RSASSA_PKCS1_V1_5_SHA1       = RSA_MAKEUP(RSASSA_PKCS1_V1_5, RSA_RESERVE, HASH_SHA1, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_V1_5_SHA224     = RSA_MAKEUP(RSASSA_PKCS1_V1_5, RSA_RESERVE, HASH_SHA224, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_V1_5_SHA256     = RSA_MAKEUP(RSASSA_PKCS1_V1_5, RSA_RESERVE, HASH_SHA256, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_V1_5_SHA384     = RSA_MAKEUP(RSASSA_PKCS1_V1_5, RSA_RESERVE, HASH_SHA384, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_V1_5_SHA512     = RSA_MAKEUP(RSASSA_PKCS1_V1_5, RSA_RESERVE, HASH_SHA512, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1   = RSA_MAKEUP(RSASSA_PKCS1_PSS, MGF_V1, HASH_SHA1, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 = RSA_MAKEUP(RSASSA_PKCS1_PSS, MGF_V1, HASH_SHA224, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 = RSA_MAKEUP(RSASSA_PKCS1_PSS, MGF_V1, HASH_SHA256, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 = RSA_MAKEUP(RSASSA_PKCS1_PSS, MGF_V1, HASH_SHA384, RSA_SIGN),
	HISEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 = RSA_MAKEUP(RSASSA_PKCS1_PSS, MGF_V1, HASH_SHA512, RSA_SIGN),
};

enum hisee_attribute_id {
	HISEE_ATTR_RSA_OAEP_LABEL,
	HISEE_ATTR_RSA_PSS_SALT_LENGTH,
	HISEE_ATTR_RSA_MGF1_HASH
};

struct hisee_attribute {
	u32 attribute_id;
	union {
		struct {
			void *buffer;
			u32   size;
		} ref;
		struct {
			u32 a;
			u32 b;
		} value;
	} content;
};

enum rsa_key_type_e {
	ALG_RSA_STD_KEY = 0,
	ALG_RSA_CRT_KEY = 1,
};

struct hisee_rsa_pubkey {
	u32 width;
	struct basic_data e;
	struct basic_data n;
};

struct hisee_rsa_privkey {
	enum rsa_key_type_e key_type;
	u32 width;
	struct basic_data n;
	struct basic_data d;
	struct basic_data p;
	struct basic_data q;
	struct basic_data dp;
	struct basic_data dq;
	struct basic_data qinv;
};

struct hisee_rsa_keypair {
	enum rsa_key_type_e key_type;
	u32 width;
	struct basic_data e;
	struct basic_data n;
	struct basic_data d;
	struct basic_data p;
	struct basic_data q;
	struct basic_data dp;
	struct basic_data dq;
	struct basic_data qinv;
};

/*
 * @param[in/out]  : pkey ,input pubkey e, output n, std or crt privkey
 * @note           : gen rsa key:generate rsa key
 */
err_bsp_t hisee_rsa_gen_key(struct hisee_rsa_keypair *pkey);

/*
 * @brief          : hisee_rsa_calculate_pubkey
 * @param[in/out]  : pkey ,input prive key ,output pubkey
 * @note           : input prive key ,output pubkey
 */
err_bsp_t hisee_rsa_calculate_pubkey(struct hisee_rsa_keypair *pkey);

/*
 * buffer and size set to attr
 * set label for RSA oaep crypt
 */
void hisee_init_ref_attr(struct hisee_attribute *attr, u32 attribute_id,
			 void *buffer, u32 size);

/*
 * a and b set to attr
 * set saltlen for RSA pss sign
 */
void hisee_init_value_attr(struct hisee_attribute *attr, u32 attribute_id,
			   u32 a, u32 b);

/*
 * rsa sign to digest data
 * for pss, if param is null or param_cnt is 0, saltlen is digestlen
 */
err_bsp_t hisee_rsa_sign(enum hisee_rsa_algorithm algo, const struct hisee_rsa_privkey *pkey,
			 struct hisee_attribute *param, u32 param_cnt,
			 const u8 *pdigest, u32 digestlen, u8 *psign, u32 *psignlen);

/*
 * rsa verify to digest data
 * for pss, if param is null or param_cnt is 0, saltlen is digestlen
 */
err_bsp_t hisee_rsa_verify(enum hisee_rsa_algorithm algo, const struct hisee_rsa_pubkey *pkey,
			   struct hisee_attribute *param, u32 param_cnt,
			   const u8 *pdigest, u32 digestlen, u8 *psign, u32 signlen);

/*
 * rsa encrypt to digest data
 * for oaep, if param is null or param_cnt is 0, label is empty
 */
err_bsp_t hisee_rsa_encrypt(enum hisee_rsa_algorithm algo, const struct hisee_rsa_pubkey *pkey,
			    struct hisee_attribute *param, u32 param_cnt,
			    const u8 *pdin, u32 dinlen, u8 *pout, u32 *poutlen);

/*
 * rsa decrypt to digest data
 * for oaep, if param is null or param_cnt is 0, label is empty
 */
err_bsp_t hisee_rsa_decrypt(enum hisee_rsa_algorithm algo, const struct hisee_rsa_privkey *pkey,
			    struct hisee_attribute *param, u32 param_cnt,
			    const u8 *pdin, u32 dinlen, u8 *pout, u32 *poutlen);

/*
 * rsa decrypt to digest data with e
 * for oaep, if param is null or param_cnt is 0, label is empty
 */
err_bsp_t hisee_rsa_decrypt_with_e(enum hisee_rsa_algorithm algo,
				   const struct hisee_rsa_keypair *pkey,
				   struct hisee_attribute *param, u32 param_cnt,
				   const u8 *pdin, u32 dinlen, u8 *pout, u32 *poutlen);

#endif /* end of __HISEE_RSA_H__ */
