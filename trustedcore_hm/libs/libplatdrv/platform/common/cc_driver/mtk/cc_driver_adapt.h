/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ccdriver init defines
 * Author: gaobo gaobo794@huawei.com
 * Create: 2020-06-18
 */
#ifndef CC_DRIVER_ADAPT_H
#define CC_DRIVER_ADAPT_H

#include "sns_silib.h"
#include "sasi_rnd.h"
#include "sasi_hash.h"
#include "sasi_hmac.h"
#include "ssi_aes.h"
#include "sasi_des.h"
#include "ssi_util_cmac.h"
#include "sasi_aesccm.h"
#include "sasi_rsa_types.h"
#include "sasi_rsa_build.h"
#include "sasi_rsa_kg.h"
#include "sasi_rsa_prim.h"
#include "sasi_rsa_schemes.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_build.h"
#include "sasi_ecpki_kg.h"
#include "sasi_ecpki_ecdsa.h"
#include "sasi_ecpki_dh.h"
#include "sasi_dh.h"
#include "sasi_ecpki_domain.h"
#include "cc_driver_hal.h"
#include "crypto_driver_adaptor.h"

#define DX_DES_KEY_SIZE_IN_BYTES SaSi_DES_KEY_SIZE_IN_BYTES
#define DX_RSA_CRT SaSi_RSA_Crt
#define DX_RSA_NO_CRT SaSi_RSA_NoCrt
#define DX_PKCS1_VER15 SaSi_PKCS1_VER15
#define DX_EC_POINT_UNCOMPRESSED SaSi_EC_PointUncompressed
#define DX_EC_MAX_PUBLIC_KEY_LEN  (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 2 * sizeof(uint32_t) + 1)
#define DX_CHECK_POINTERS_SIZES_ONLY CheckPointersAndSizesOnly
#define DX_DH_PKCS3_MODE SaSi_DH_PKCS3_mode

struct hash_ctx_t {
    int32_t hash_mode;
    SaSi_HASHUserContext_t ctx;
};

struct hmac_ctx_t {
    int32_t hash_mode;
    SaSi_HMACUserContext_t ctx;
};

struct cipher_ctx_t {
    uint32_t alg_type;
    union {
        SaSiAesUserContext_t aes;
        SaSi_DESUserContext_t des;
    } ctx;
};

typedef SaSi_RND_Context_t dx_rand_ctx_t;
typedef SaSi_RND_WorkBuff_t dx_rand_work_buf_t;
typedef SaSi_HASH_Result_t hash_result_buf_t;
typedef SaSi_AESCCM_UserContext_t aes_ccm_ctx_t;
typedef SaSi_DES_Iv_t des_iv_t;
typedef SaSi_DES_Key_t des_key_t;
typedef SaSi_AESCCM_Key_t aes_ccm_key_t;
typedef SaSi_AESCCM_Mac_Res_t aes_ccm_mac_res_t;
typedef SaSi_RSAUserPrivKey_t dx_rsa_user_priv_key_t;
typedef SaSiRSAPrivKey_t dx_rsa_priv_key_t;
typedef SaSi_RSAPrivUserContext_t dx_rsa_priv_user_ctx_t;
typedef SaSi_RSAUserPubKey_t dx_rsa_user_pub_key_t;
typedef SaSi_RSAPubUserContext_t dx_rsa_pub_user_ctx_t;
typedef SaSi_RSAKGData_t dx_rsa_kg_data_t;
typedef SaSi_RSAPrimeData_t dx_rsa_prime_data_t;
typedef SaSi_ECPKI_UserPublKey_t dx_ecc_user_pub_key_t;
typedef struct SaSi_ECPKI_PublKey_t dx_ecc_pub_key_t;
typedef SaSi_ECPKI_UserPrivKey_t dx_ecc_user_priv_key_t;
typedef SaSi_ECPKI_PrivKey_t dx_ecc_priv_key_t;
typedef SaSi_ECPKI_KG_TempData_t dx_ecc_kg_temp_data_t;
typedef SaSi_ECDSA_SignUserContext_t dx_ecc_sign_user_ctx_t;
typedef SaSi_ECPKI_BUILD_TempData_t dx_ecc_build_temp_data_t;
typedef SaSi_ECDSA_VerifyUserContext_t dx_ecc_verify_user_ctx_t;
typedef SaSi_ECDH_TempData_t dx_ecdh_temp_data_t;
typedef SaSi_DHUserPubKey_t dx_dh_user_pub_key_t;
typedef SaSi_DHPrimeData_t dx_dh_prime_data_t;

#define GET_DX_EC_KEY_DOMAINID(key) ((key)->domain.DomainID)

struct alg_to_hash_mode_len_t {
    uint32_t alg_type;
    int32_t hash_mode;
    uint32_t hash_len;
};
static const struct alg_to_hash_mode_len_t g_hash_mode_len[] = {
    { CRYPTO_TYPE_DIGEST_MD5,    SaSi_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_DIGEST_SHA1,   SaSi_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_DIGEST_SHA224, SaSi_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_DIGEST_SHA256, SaSi_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_DIGEST_SHA384, SaSi_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_DIGEST_SHA512, SaSi_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_HMAC_MD5,      SaSi_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_HMAC_SHA1,     SaSi_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_HMAC_SHA224,   SaSi_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_HMAC_SHA256,   SaSi_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_HMAC_SHA384,   SaSi_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_HMAC_SHA512,   SaSi_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_ECDSA_SHA1,    SaSi_ECPKI_AFTER_HASH_SHA1_mode,   SHA1_LEN },
    { CRYPTO_TYPE_ECDSA_SHA224,  SaSi_ECPKI_AFTER_HASH_SHA224_mode, SHA224_LEN },
    { CRYPTO_TYPE_ECDSA_SHA256,  SaSi_ECPKI_AFTER_HASH_SHA256_mode, SHA256_LEN },
    { CRYPTO_TYPE_ECDSA_SHA384,  SaSi_ECPKI_AFTER_HASH_SHA384_mode, SHA384_LEN },
    { CRYPTO_TYPE_ECDSA_SHA521,  SaSi_ECPKI_AFTER_HASH_SHA512_mode, SHA512_LEN },
};

struct alg_to_cipher_mode_t {
    uint32_t alg_type;
    uint32_t drv_mode;
};
static const struct alg_to_cipher_mode_t g_cipher_mode[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,      SASI_AES_MODE_ECB },
    { CRYPTO_TYPE_AES_CBC_NOPAD,      SASI_AES_MODE_CBC },
    { CRYPTO_TYPE_AES_CTR,            SASI_AES_MODE_CTR },
    { CRYPTO_TYPE_AES_CTS,            SASI_AES_MODE_CBC_CTS },
    { CRYPTO_TYPE_AES_XTS,            SASI_AES_MODE_XTS },
    { CRYPTO_TYPE_AES_CMAC,           SASI_AES_MODE_CMAC },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,  SASI_AES_MODE_CBC_MAC },
    { CRYPTO_TYPE_DES_ECB_NOPAD,      SaSi_DES_ECB_mode },
    { CRYPTO_TYPE_DES_CBC_NOPAD,      SaSi_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,     SaSi_DES_ECB_mode },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,     SaSi_DES_CBC_mode },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,  SaSi_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD, SaSi_DES_CBC_mode },
};

struct key_size_to_key_id_t {
    uint32_t key_size;
    int32_t key_id;
};
static const struct key_size_to_key_id_t g_key_size_id[] = {
    { AES_KEY_16_BYTES, SaSi_AES_Key128BitSize },
    { AES_KEY_24_BYTES, SaSi_AES_Key192BitSize },
    { AES_KEY_32_BYTES, SaSi_AES_Key256BitSize },
    { AES_KEY_64_BYTES, SaSi_AES_Key512BitSize },
};
static inline int32_t get_cc_sym_key_size_id(const struct symmerit_key_t *key)
{
    for (uint32_t i = 0; i < (sizeof(g_key_size_id) / sizeof(g_key_size_id[0])); i++) {
        if (g_key_size_id[i].key_size == key->key_size)
            return g_key_size_id[i].key_id;
    }

    return INVALID_KEY_SIZE_ID;
}
struct cc_rsa_info_t {
    SaSi_RSA_HASH_OpMode_t hash_mode;
    SaSi_PKCS1_MGF_t pkcs1_mgf;
    SaSi_PKCS1_version pkcs1_version;
};

static inline int32_t get_cipher_drv_mode(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_cipher_mode) / sizeof(g_cipher_mode[0])); i++) {
        if (g_cipher_mode[i].alg_type == alg_type)
            return g_cipher_mode[i].drv_mode;
    }

    return INVALID_DRV_MODE;
}

struct rsa_alg_to_sign_info_t {
    uint32_t alg_type;
    struct cc_rsa_info_t sign_info;
};

static const struct rsa_alg_to_sign_info_t g_rsa_alg_to_sign_info[] = {
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5,        { SaSi_RSA_After_MD5_mode,    SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1,       { SaSi_RSA_After_SHA1_mode,   SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224,     { SaSi_RSA_After_SHA224_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256,     { SaSi_RSA_After_SHA256_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384,     { SaSi_RSA_After_SHA384_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512,     { SaSi_RSA_After_SHA512_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,    { SaSi_RSA_After_MD5_mode,    SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,   { SaSi_RSA_After_SHA1_mode,   SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, { SaSi_RSA_After_SHA224_mode, SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, { SaSi_RSA_After_SHA256_mode, SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, { SaSi_RSA_After_SHA384_mode, SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, { SaSi_RSA_After_SHA512_mode, SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
};

struct rsa_alg_to_ency_info_t {
    uint32_t alg_type;
    struct cc_rsa_info_t ency_info;
};

static const struct rsa_alg_to_ency_info_t g_rsa_alg_to_ency_info[] = {
    { CRYPTO_TYPE_RSA_NO_PAD,                   { SaSi_RSA_HASH_NO_HASH_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_V1_5,             { SaSi_RSA_HASH_NO_HASH_mode, SaSi_PKCS1_NO_MGF, SaSi_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1,   { SaSi_RSA_HASH_SHA1_mode,    SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224, { SaSi_RSA_HASH_SHA224_mode,  SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256, { SaSi_RSA_HASH_SHA256_mode,  SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384, { SaSi_RSA_HASH_SHA384_mode,  SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512, { SaSi_RSA_HASH_SHA512_mode,  SaSi_PKCS1_MGF1,   SaSi_PKCS1_VER21 } },
};

struct ecc_curve_domain_t {
    uint32_t curve_id;
    int32_t domain_id;
    uint32_t key_size;
};

static const struct ecc_curve_domain_t g_ecc_curve_domain[] = {
    { ECC_CURVE_NIST_P192, SaSi_ECPKI_DomainID_secp192r1, ECC_192_KEY_SIZE },
    { ECC_CURVE_NIST_P224, SaSi_ECPKI_DomainID_secp224r1, ECC_224_KEY_SIZE },
    { ECC_CURVE_NIST_P256, SaSi_ECPKI_DomainID_secp256r1, ECC_256_KEY_SIZE },
    { ECC_CURVE_NIST_P384, SaSi_ECPKI_DomainID_secp384r1, ECC_384_KEY_SIZE },
    { ECC_CURVE_NIST_P521, SaSi_ECPKI_DomainID_secp521r1, ECC_521_KEY_SIZE },
};

/* The following five functions are not declared in the DX header file, so declare them here */
void DX_Clock_Init(void);
void DX_Clock_Uninit(void);
SaSiError_t SaSi_AESCCM_Init_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, SaSiAesEncryptMode_t EncrDecrMode,
                                 SaSi_AESCCM_Key_t CCM_Key, SaSi_AESCCM_KeySize_t KeySizeId, uint32_t AdataSize,
                                 uint32_t TextSize, uint8_t *N_ptr, uint8_t SizeOfN, uint8_t SizeOfT);
SaSiError_t SaSi_AESCCM_BlockTextData_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                          uint32_t DataInSize, uint8_t *DataOut_ptr);
CEXPORT_C SaSiError_t SaSi_AESCCM_Finish_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                             uint32_t DataInSize, uint8_t *DataOut_ptr, SaSi_AESCCM_Mac_Res_t MacRes,
                                             uint8_t *SizeOfT);

#define cc_hash_init SaSi_HASH_Init_MTK
#define cc_hash_update SaSi_HASH_Update_MTK
#define cc_hash_finish SaSi_HASH_Finish_MTK

#define cc_hmac_init SaSi_HMAC_Init_MTK
#define cc_hmac_update SaSi_HMAC_Update_MTK
#define cc_hmac_finish SaSi_HMAC_Finish_MTK

#define cc_aes_block SaSi_AesBlock

#define cc_des_init SaSi_DES_Init_MTK
#define cc_des_block SaSi_DES_Block_MTK

#define cc_aes_ccm_init SaSi_AESCCM_Init_MTK
#define cc_aes_ccm_update_aad SaSi_AESCCM_BlockAdata_MTK
#define cc_aes_ccm_update_data SaSi_AESCCM_BlockTextData_MTK
#define cc_aes_ccm_finish SaSi_AESCCM_Finish_MTK

#define cc_rsa_build_priv_key SaSi_RSA_Build_PrivKey_MTK
#define cc_rsa_build_priv_key_crt SaSi_RSA_Build_PrivKeyCRT_MTK
#define cc_rsa_build_pub_key SaSi_RSA_Build_PubKey_MTK
#define cc_rsa_verify SaSi_RsaVerify
#define cc_rsa_get_pub_key SaSi_RSA_Get_PubKey_MTK
#define cc_rsa_get_priv_key SaSi_RSA_Get_PrivKey
#define cc_rsa_get_priv_key_crt SaSi_RSA_Get_PrivKeyCRT
#define cc_rsa_prim_encrypt SaSi_RSA_PRIM_Encrypt_MTK
#define cc_rsa_prim_decrypt SaSi_RSA_PRIM_Decrypt_MTK
#define cc_rsa_schemes_decrypt SaSi_RsaSchemesDecrypt

#define cc_ecc_export_pub_key SaSi_ECPKI_ExportPublKey_MTK
#define cc_ecc_verify SaSi_ECDSA_Verify_MTK
#define cc_ecdh_svdp_dh SaSi_ECDH_SVDP_DH_MTK

#define cc_dh_get_secret_key SaSi_DH_GetSecretKey_MTK

#define cc_cmac_derive_key(user_key, data_in, data_in_size, mac_res) \
    SaSi_UtilCmacDeriveKey(SASI_UTIL_ROOT_KEY, user_key, data_in, data_in_size, mac_res)

#define cc_lib_init(rnd_ctx, rnd_work_buf, is_fips, fips_ctx) \
    SaSi_LibInit(rnd_ctx, rnd_work_buf, is_fips, fips_ctx)

#define cc_rand_generate_vector(rnd_state, size, buffer) \
    SaSi_RND_GenerateVector_MTK(rnd_state, size, buffer)

#define cc_rsa_sign(rnd_ctx, cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version) \
    SaSi_RsaSign(rnd_ctx, cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version)

#define cc_rsa_generate_key_pair(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    SaSi_RSA_KG_GenerateKeyPair_MTK(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx)

#define cc_rsa_generate_key_pair_crt(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    SaSi_RSA_KG_GenerateKeyPairCRT_MTK(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx)

#define cc_rsa_schemes_encrypt(rnd_ctx, pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version) \
    SaSi_RsaSchemesEncrypt(rnd_ctx, pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version)

#define cc_ecc_generate_key_pair(rnd_ctx, domain_id, priv_key, pub_key, tmp_data, fis_ctx) \
    SaSi_ECPKI_GenKeyPair_MTK(rnd_ctx, SaSi_ECPKI_GetEcDomain(domain_id), priv_key, pub_key, tmp_data, fis_ctx)

#define cc_ecc_build_priv_key(domain_id, priv_key, priv_key_len, user_priv_key) \
    SaSi_ECPKI_BuildPrivKey_MTK(SaSi_ECPKI_GetEcDomain(domain_id), priv_key, priv_key_len, user_priv_key)

#define cc_ecc_build_pub_key(domain_id, pub_key, pub_key_len, check_mode, user_pub_key, tmp_data) \
    _DX_ECPKI_BuildPublKey_MTK(SaSi_ECPKI_GetEcDomain(domain_id), pub_key, pub_key_len, check_mode, \
    user_pub_key, tmp_data)

#define cc_ecc_sign(rnd_ctx, user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len) \
    SaSi_ECDSA_Sign_MTK(rnd_ctx, user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len)

#define cc_dh_generate_pub_priv(rnd_ctx, generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, priv_key_len, pub_key, pub_key_len) \
    _DX_DH_GeneratePubPrv_MTK(rnd_ctx, generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, (uint16_t *)priv_key_len, pub_key, (uint16_t *)pub_key_len)

void set_secs_suspend_flag(void);
int32_t dxcc_power_on(void);
int32_t dxcc_power_off(void);
int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv);
int32_t dxcc_aes_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

dx_rand_ctx_t *get_rnd_context_ptr(void);
dx_rand_work_buf_t *get_rnd_workbuff_ptr(void);
#endif
