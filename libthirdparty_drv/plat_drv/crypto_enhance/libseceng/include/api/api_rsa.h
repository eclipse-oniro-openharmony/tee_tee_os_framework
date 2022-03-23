/**
 * @file   : api_rsa.h
 * @par    : Copyright(c) 2018-2019, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/06
 * @author : z00293770
 */
#ifndef __API_RSA_H__
#define __API_RSA_H__
#include <pal_types.h>

/* the abstracts data structure for the API layer */
typedef struct api_param_struct {
	u32    operation_mode;        /* The value must be in opera_mode_e */
	u32    sub_mode;    /* sub mode can be key type or protocol type, refer to the API function */
	void    *object;        /* the abstracts data structure , refer to the API function */
} api_param_s;

/* enum for operation_mode */
typedef enum {
	OPERATION_RSA_GEN_KEY = 0,
	OPERATION_RSA_ENCRYPT = 1,
	OPERATION_RSA_DECRYPT = 2,
	OPERATION_RSA_SIGN = 3,
	OPERATION_RSA_VERIFY = 4,
	OPERATION_UNKNOWN,
} opera_mode_e;

/* RSA keypair type */
typedef enum {
	ALG_RSA_STD_KEY = 0,
	ALG_RSA_CRT_KEY = 1,
	ALG_RSA_UNKNOWN_KEY_TYPE,
} rsa_key_type_e;

/* RSA crypto type: support nopad(prime), PKCS#1-V1.5,  PKCS#1-PSS */
typedef enum {
	ALG_RSAES_NOPAD = 0,
	ALG_RSAES_PKCS1_V15  = 1,
	ALG_RSAES_PKCS1_OAEP = 2,
	ALG_RSAES_UNKNOWN,
} rsa_crypto_e;

/* RSA signature type: support PKCS#1-V1.5,  PKCS#1-PSS and custom of ChinaDRM */
typedef enum {
	ALG_RSASSA_PKCS1_V15  = 0,
	ALG_RSASSA_PKCS1_PSS = 1,
	ALG_RSASSA_PKCS1_V15_CLIENTSK  = 2,
	ALG_RSASSA_PKCS1_PSS_CLIENTSK = 3,
} rsa_sign_e;

/* the keypair structure */
typedef struct api_rsa_key_struct {
	u32    key_type;    /* support STDKEY(noCRT) and CRT key */
	void    *key_info;    /* the detail info for keypair */
} api_rsa_key_s;

typedef struct api_rsa_nopad_crypto_struct {
	api_rsa_key_s        *pkey_s;
	const u8            *pdin;
	u32                inlen;
	u8                *pdout;
	u32                *pout_len;
} api_rsa_nopad_crypto_s;

typedef struct api_rsa_pkcs_v1_5_crypto_struct {
	api_rsa_key_s        *pkey_s;
	const u8            *pdin;
	u32                inlen;
	u8                *pdout;
	u32                *pout_len;
} api_rsa_pkcs_v1_5_crypto_s;

typedef struct api_rsa_oaep_crypt_info_struct {
	u32        hashmode;
	u32        MGFmode;
	const u8    *plabel;
	u32        label_len;
} api_rsa_oaep_crypto_info_s;

typedef struct api_rsa_oaep_crypto_struct {
	api_rsa_key_s        *pkey_s;
	api_rsa_oaep_crypto_info_s    oaep_info;
	const u8            *pdin;
	u32                inlen;
	u8                *pdout;
	u32                *pout_len;
} api_rsa_oaep_crypto_s;

typedef struct api_rsa_pkcs_v1_5_sign_struct {
	api_rsa_key_s    *pkey_s;
	u32            hashmode;
	const u8        *pdin;
	u32            inlen;
	u8            *psign;
} api_rsa_pkcs_v1_5_sign_s;

typedef struct api_rsa_pss_sign_struct {
	api_rsa_key_s    *pkey_s;
	u32            hashmode;
	u32            MGFmode;
	u32            saltlen;
	const u8        *pdin;
	u32            inlen;
	u8            *psign;
} api_rsa_pss_sign_s;

typedef enum {
	HASH_SHA1_MODE = 0,    /* HASH SHA1 */
	HASH_SHA256_MODE = 1,    /* HASH SHA256 */
	HASH_AFTER_SHA1_MODE = 2,    /* HASH after SHA1 */
	HASH_AFTER_SHA256_MODE = 3,    /* HASH after SHA256 */
	HASH_MODE_UNKNOWN,
} hash_mode_e;

/* MGF version */
typedef enum {
	MGF_PKCS1_MGF1 = 0,
	MGF_UNKNOWN,
} MGF_mode_e;

typedef struct {
	u32   size;
	u8    *pdata;
} api_rsa_data_s;

/**
 * @brief      : api_rsa_gen_keypair
 * @param[in]  : pkey_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_GEN_KEY
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa key type, please see rsa_key_type_e
			ALG_RSA_STD_KEY
			ALG_RSA_CRT_KEY
 *             object (in api_param_s struct) - the detail structure when generate rsa keypair
			if key type is ALG_RSA_STD_KEY, the object is the pointer to hal_rsa_key_s structure
			if key type is ALG_RSA_CRT_KEY, the object is the pointer to hal_rsa_crtkey_s structure
 * @return     : ::err_bsp_t error code
 * @note       :generate rsa keypair
 */
err_bsp_t api_rsa_gen_keypair(api_param_s *pkey_s);

/**
 * @brief      : api_rsa_encrypt
 * @param[in]  : pcrypto_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_ENCRYPT
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa crypto type(the protocol type when encrypto), please see rsa_crypto_e
			ALG_RSAES_NOPAD
			ALG_RSAES_PKCS1_V15
			ALG_RSAES_PKCS1_OAEP
 *             object (in api_param_s struct) - the detail structure when encrypto
			if crypto type is ALG_RSAES_NOPAD, the object is the pointer to api_rsa_nopad_crypto_s structure
			if crypto type is ALG_RSAES_PKCS1_V15, the object is the pointer to api_rsa_pkcs_v1_5_crypto_s structure
			if crypto type is ALG_RSAES_PKCS1_OAEP, the object is the pointer to api_rsa_oaep_crypto_s structure
 * @return     : ::err_bsp_t error code
 * @note       :rsa encrypt process
 */
err_bsp_t api_rsa_encrypt(api_param_s *pcrypto_s);

/**
 * @brief      : api_rsa_decrypt
 * @param[in]  : pcrypto_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_DECRYPT
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa crypto type(the protocol type when decrypto), please see rsa_crypto_e
			ALG_RSAES_NOPAD
			ALG_RSAES_PKCS1_V15
			ALG_RSAES_PKCS1_OAEP
 *             object (in api_param_s struct) - the detail structure when decrypto
			if crypto type is ALG_RSAES_NOPAD, the object is the pointer to api_rsa_nopad_crypto_s structure
			if crypto type is ALG_RSAES_PKCS1_V15, the object is the pointer to api_rsa_pkcs_v1_5_crypto_s structure
			if crypto type is ALG_RSAES_PKCS1_OAEP, the object is the pointer to api_rsa_oaep_crypto_s structure
 * @return     : ::err_bsp_t error code
 * @note       :rsa decrypt process
 */
err_bsp_t api_rsa_decrypt(api_param_s *pcrypto_s);

/**
 * @brief      : api_rsa_sign
 * @param[in]  : psign_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_SIGN
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa signature type(the protocol type when signature), please see rsa_sign_e
			ALG_RSASSA_PKCS1_V15,
			ALG_RSASSA_PKCS1_PSS,
			ALG_RSASSA_PKCS1_V15_CLIENTSK: base on v1.5, custom of ChinaDRM
			ALG_RSASSA_PKCS1_PSS_CLIENTSK: base on pss, custom of ChinaDRM
 *             object (in api_param_s struct) - the detail structure when signature
			if signature type is ALG_RSASSA_PKCS1_V15/ALG_RSASSA_PKCS1_V15_CLIENTSK
			the object is the pointer to api_rsa_pkcs_v1_5_sign_s structure
			if signature type is ALG_RSASSA_PKCS1_PSS/ALG_RSASSA_PKCS1_PSS_CLIENTSK,
			the object is the pointer to api_rsa_pss_sign_s structure
 * @return     : ::err_bsp_t error code
 * @note       :rsa signature process
 */
err_bsp_t api_rsa_sign(api_param_s *psign_s);

/**
 * @brief      : api_rsa_verify
 * @param[in]  : pverify_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_SIGN
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa signature type(the protocol type when signature)
			ALG_RSASSA_PKCS1_V15
			ALG_RSASSA_PKCS1_PSS
 *             object (in api_param_s struct) - the detail structure when verify the signature
			if verify type is ALG_RSASSA_PKCS1_V15
			the object is the pointer to api_rsa_pkcs_v1_5_sign_s structure
			if verify type is ALG_RSASSA_PKCS1_PSS
			the object is the pointer to api_rsa_pss_sign_s structure
 * @return     : ::err_bsp_t error code
 * @note       :rsa signature verify process
 */
err_bsp_t api_rsa_verify(api_param_s *pverify_s);

/**
 * @brief      : api_rsa_bnmul
 * @param[in]  : pmul_a  multiply data a
 * @param[in]  : pmul_b multiply data b
 * @param[out]  : pout_c , the out data
 * @return     : ::err_bsp_t, error code
 * @note       :c = a * b
 */
err_bsp_t api_rsa_bnmul(api_rsa_data_s *pmul_a, api_rsa_data_s *pmul_b, api_rsa_data_s *pout_c);

/**
 * @brief      : api_rsa_sign , custom for ChinaDRM , the private key is encrypto by clientSK
 * @param[in]  : psign_s point to the struct api_param_s
 *             operation_mode (in api_param_s struct) - must be OPERATION_RSA_SIGN
			please see opera_mode_e
 *             sub_mode (in api_param_s struct) - rsa signature type(the protocol type when signature), please see rsa_sign_e
			ALG_RSASSA_PKCS1_V15_CLIENTSK: base on v1.5, custom for ChinaDRM
			ALG_RSASSA_PKCS1_PSS_CLIENTSK: base on pss, custom for ChinaDRM
 *             object (in api_param_s struct) - the detail structure when signature
			if signature type is ALG_RSASSA_PKCS1_V15_CLIENTSK
			the object is the pointer to api_rsa_pkcs_v1_5_sign_s structure
			if signature type is ALG_RSASSA_PKCS1_PSS_CLIENTSK
			the object is the pointer to api_rsa_pss_sign_s structure
 * @return     : ::err_bsp_t error code
 * @note       :rsa signature process , custom for ChinaDRM
			the private key is encrypto by clientSK, need to decrypto private key by clientSK, before signature
 */
err_bsp_t api_rsa_sign_clientSK(api_param_s *psign_s);

#endif /* end of __API_RSA_H__ */
