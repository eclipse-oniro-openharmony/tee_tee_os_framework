/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ccdriver init defines
 * Create: 2020-06-18
 */
#ifndef CC_DRIVER_ADAPT_H
#define CC_DRIVER_ADAPT_H

#include "crys_hash.h"
#include "crys_hmac.h"
#include "crys_aes.h"
#include "crys_des.h"
#include "crys_aesccm.h"
#include "crys_rsa_types.h"
#include "crys_rsa_kg.h"
#include "crys_rsa_build.h"
#include "crys_rsa_prim.h"
#include "crys_rsa_schemes.h"
#include "crys_ecpki_types.h"
#include "crys_ecpki_kg.h"
#include "crys_ecpki_build.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_dh.h"
#include "crys_dh.h"
#include "dx_util.h"
#include "dx_cclib.h"
#include "crys_rnd.h"
#include "cc_driver_hal.h"
#if (TRUSTEDCORE_PLATFORM_CHOOSE != WITH_HUANGLONG_PLATFORM && \
    TRUSTEDCORE_PLATFORM_CHOOSE != WITH_BALONG_PLATFORM)
#include "cc_power.h"
#endif
#include "crypto_driver_adaptor.h"

#define DX_DES_KEY_SIZE_IN_BYTES CRYS_DES_KEY_SIZE_IN_BYTES
#define DX_RSA_CRT CRYS_RSA_Crt
#define DX_RSA_NO_CRT CRYS_RSA_NoCrt
#define DX_PKCS1_VER15 CRYS_PKCS1_VER15
#define DX_EC_POINT_UNCOMPRESSED CRYS_EC_PointUncompressed
#define DX_EC_MAX_PUBLIC_KEY_LEN  (CRYS_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 2 * sizeof(uint32_t) + 1)
#define DX_CHECK_POINTERS_SIZES_ONLY CheckPointersAndSizesOnly
#define DX_DH_PKCS3_MODE CRYS_DH_PKCS3_mode

struct hash_ctx_t {
    int32_t hash_mode;
    CRYS_HASHUserContext_t ctx;
};

struct hmac_ctx_t {
    int32_t hash_mode;
    CRYS_HMACUserContext_t ctx;
};

struct cipher_ctx_t {
    uint32_t alg_type;
    union {
        CRYS_AESUserContext_t aes;
        CRYS_DESUserContext_t des;
    } ctx;
};

typedef uint32_t dx_rand_ctx_t[CRYS_DES_KEY_SIZE_IN_BYTES];
typedef uint32_t dx_rand_work_buf_t[CRYS_DES_KEY_SIZE_IN_BYTES];
typedef CRYS_HASH_Result_t hash_result_buf_t;
typedef CRYS_AESCCM_UserContext_t aes_ccm_ctx_t;
typedef CRYS_DES_Iv_t des_iv_t;
typedef CRYS_DES_Key_t des_key_t;
typedef CRYS_AESCCM_Key_t aes_ccm_key_t;
typedef CRYS_AESCCM_Mac_Res_t aes_ccm_mac_res_t;
typedef CRYS_RSAUserPrivKey_t dx_rsa_user_priv_key_t;
typedef CRYSRSAPrivKey_t dx_rsa_priv_key_t;
typedef CRYS_RSAPrivUserContext_t dx_rsa_priv_user_ctx_t;
typedef CRYS_RSAUserPubKey_t dx_rsa_user_pub_key_t;
typedef CRYS_RSAPubUserContext_t dx_rsa_pub_user_ctx_t;
typedef CRYS_RSAKGData_t dx_rsa_kg_data_t;
typedef CRYS_RSAPrimeData_t dx_rsa_prime_data_t;
typedef CRYS_ECPKI_UserPublKey_t dx_ecc_user_pub_key_t;
typedef CRYS_ECPKI_PublKey_t dx_ecc_pub_key_t;
typedef CRYS_ECPKI_UserPrivKey_t dx_ecc_user_priv_key_t;
typedef CRYS_ECPKI_PrivKey_t dx_ecc_priv_key_t;
typedef CRYS_ECPKI_KG_TempData_t dx_ecc_kg_temp_data_t;
typedef CRYS_ECDSA_SignUserContext_t dx_ecc_sign_user_ctx_t;
typedef CRYS_ECPKI_BUILD_TempData_t dx_ecc_build_temp_data_t;
typedef CRYS_ECDSA_VerifyUserContext_t dx_ecc_verify_user_ctx_t;
typedef CRYS_ECDH_TempData_t dx_ecdh_temp_data_t;
typedef CRYS_DHUserPubKey_t dx_dh_user_pub_key_t;
typedef CRYS_DHPrimeData_t dx_dh_prime_data_t;

#define GET_DX_EC_KEY_DOMAINID(key) ((key)->DomainID)

struct alg_to_hash_mode_len_t {
    uint32_t alg_type;
    int32_t hash_mode;
    uint32_t hash_len;
};
static const struct alg_to_hash_mode_len_t g_hash_mode_len[] = {
    { CRYPTO_TYPE_DIGEST_MD5,    CRYS_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_DIGEST_SHA1,   CRYS_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_DIGEST_SHA224, CRYS_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_DIGEST_SHA256, CRYS_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_DIGEST_SHA384, CRYS_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_DIGEST_SHA512, CRYS_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_HMAC_MD5,      CRYS_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_HMAC_SHA1,     CRYS_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_HMAC_SHA224,   CRYS_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_HMAC_SHA256,   CRYS_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_HMAC_SHA384,   CRYS_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_HMAC_SHA512,   CRYS_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_ECDSA_SHA1,    CRYS_ECPKI_AFTER_HASH_SHA1_mode,   SHA1_LEN },
    { CRYPTO_TYPE_ECDSA_SHA224,  CRYS_ECPKI_AFTER_HASH_SHA224_mode, SHA224_LEN },
    { CRYPTO_TYPE_ECDSA_SHA256,  CRYS_ECPKI_AFTER_HASH_SHA256_mode, SHA256_LEN },
    { CRYPTO_TYPE_ECDSA_SHA384,  CRYS_ECPKI_AFTER_HASH_SHA384_mode, SHA384_LEN },
    { CRYPTO_TYPE_ECDSA_SHA521,  CRYS_ECPKI_AFTER_HASH_SHA512_mode, SHA512_LEN },
};

struct alg_to_cipher_mode_t {
    uint32_t alg_type;
    uint32_t drv_mode;
};
static const struct alg_to_cipher_mode_t g_cipher_mode[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,      CRYS_AES_ECB_mode },
    { CRYPTO_TYPE_AES_CBC_NOPAD,      CRYS_AES_CBC_mode },
    { CRYPTO_TYPE_AES_CTR,            CRYS_AES_CTR_mode },
    { CRYPTO_TYPE_AES_CTS,            CRYS_AES_CBC_CTS_mode },
    { CRYPTO_TYPE_AES_XTS,            CRYS_AES_XTS_mode },
    { CRYPTO_TYPE_AES_CMAC,           CRYS_AES_CMAC_mode },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,  CRYS_AES_MAC_mode },
    { CRYPTO_TYPE_DES_ECB_NOPAD,      CRYS_DES_ECB_mode },
    { CRYPTO_TYPE_DES_CBC_NOPAD,      CRYS_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,     CRYS_DES_ECB_mode },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,     CRYS_DES_CBC_mode },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,  CRYS_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD, CRYS_DES_CBC_mode },
};

struct key_size_to_key_id_t {
    uint32_t key_size;
    int32_t key_id;
};
static const struct key_size_to_key_id_t g_key_size_id[] = {
    { AES_KEY_16_BYTES, CRYS_AES_Key128BitSize },
    { AES_KEY_24_BYTES, CRYS_AES_Key192BitSize },
    { AES_KEY_32_BYTES, CRYS_AES_Key256BitSize },
    { AES_KEY_64_BYTES, CRYS_AES_Key512BitSize },
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
    CRYS_RSA_HASH_OpMode_t hash_mode;
    CRYS_PKCS1_MGF_t pkcs1_mgf;
    CRYS_PKCS1_version pkcs1_version;
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
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5,        { CRYS_RSA_After_MD5_mode,    CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1,       { CRYS_RSA_After_SHA1_mode,   CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224,     { CRYS_RSA_After_SHA224_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256,     { CRYS_RSA_After_SHA256_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384,     { CRYS_RSA_After_SHA384_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512,     { CRYS_RSA_After_SHA512_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,    { CRYS_RSA_After_MD5_mode,    CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,   { CRYS_RSA_After_SHA1_mode,   CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, { CRYS_RSA_After_SHA224_mode, CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, { CRYS_RSA_After_SHA256_mode, CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, { CRYS_RSA_After_SHA384_mode, CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, { CRYS_RSA_After_SHA512_mode, CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
};

struct rsa_alg_to_ency_info_t {
    uint32_t alg_type;
    struct cc_rsa_info_t ency_info;
};
static const struct rsa_alg_to_ency_info_t g_rsa_alg_to_ency_info[] = {
    { CRYPTO_TYPE_RSA_NO_PAD,                   { CRYS_RSA_HASH_NO_HASH_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_V1_5,             { CRYS_RSA_HASH_NO_HASH_mode, CRYS_PKCS1_NO_MGF, CRYS_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1,   { CRYS_RSA_HASH_SHA1_mode,    CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224, { CRYS_RSA_HASH_SHA224_mode,  CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256, { CRYS_RSA_HASH_SHA256_mode,  CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384, { CRYS_RSA_HASH_SHA384_mode,  CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512, { CRYS_RSA_HASH_SHA512_mode,  CRYS_PKCS1_MGF1,   CRYS_PKCS1_VER21 } },
};

struct ecc_curve_domain_t {
    uint32_t curve_id;
    int32_t domain_id;
    uint32_t key_size;
};

static const struct ecc_curve_domain_t g_ecc_curve_domain[] = {
    { ECC_CURVE_NIST_P192, CRYS_ECPKI_DomainID_secp192r1, ECC_192_KEY_SIZE },
    { ECC_CURVE_NIST_P224, CRYS_ECPKI_DomainID_secp224r1, ECC_224_KEY_SIZE },
    { ECC_CURVE_NIST_P256, CRYS_ECPKI_DomainID_secp256r1, ECC_256_KEY_SIZE },
    { ECC_CURVE_NIST_P384, CRYS_ECPKI_DomainID_secp384r1, ECC_384_KEY_SIZE },
    { ECC_CURVE_NIST_P521, CRYS_ECPKI_DomainID_secp521r1, ECC_521_KEY_SIZE },
};
#define cc_hash_init CRYS_HASH_Init
#define cc_hash_update CRYS_HASH_Update
#define cc_hash_finish CRYS_HASH_Finish

#define cc_hmac_init CRYS_HMAC_Init
#define cc_hmac_update CRYS_HMAC_Update
#define cc_hmac_finish CRYS_HMAC_Finish

#define cc_aes_block CRYS_AES_Block

#define cc_des_init CRYS_DES_Init
#define cc_des_block CRYS_DES_Block

#define cc_aes_ccm_init CRYS_AESCCM_Init
#define cc_aes_ccm_update_aad CRYS_AESCCM_BlockAdata
#define cc_aes_ccm_update_data CRYS_AESCCM_BlockTextData
#define cc_aes_ccm_finish CRYS_AESCCM_Finish

#define cc_rsa_build_priv_key CRYS_RSA_Build_PrivKey
#define cc_rsa_build_priv_key_crt CRYS_RSA_Build_PrivKeyCRT
#define cc_rsa_build_pub_key CRYS_RSA_Build_PubKey
#define cc_rsa_verify _DX_RSA_Verify
#define cc_rsa_get_pub_key CRYS_RSA_Get_PubKey
#define cc_rsa_get_priv_key CRYS_RsaGetPrivKey
#define cc_rsa_get_priv_key_crt CRYS_RsaGetPrivKeyCRT
#define cc_rsa_prim_encrypt CRYS_RSA_PRIM_Encrypt
#define cc_rsa_prim_decrypt CRYS_RSA_PRIM_Decrypt
#define cc_rsa_schemes_decrypt _DX_RSA_SCHEMES_Decrypt

#define cc_ecc_export_pub_key CRYS_ECPKI_ExportPublKey
#define cc_ecc_build_priv_key CRYS_ECPKI_BuildPrivKey
#define cc_ecc_build_pub_key _DX_ECPKI_BuildPublKey
#define cc_ecc_verify CRYS_ECDSA_Verify
#define cc_ecdh_svdp_dh CRYS_ECDH_SVDP_DH

#define cc_dh_get_secret_key CRYS_DH_GetSecretKey

#define cc_cmac_derive_key(user_key, data_in, data_in_size, mac_res) \
    DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, data_in, data_in_size, mac_res)

#define cc_lib_init(rnd_ctx, rnd_work_buf, is_fips, fips_ctx) DX_CclibInit()

#define cc_rand_generate_vector(rnd_state, size, buffer) \
    CRYS_RND_GenerateVector(size, buffer)

#define cc_rsa_sign(rnd_ctx, cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version) \
    _DX_RSA_Sign(cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version)

#define cc_rsa_generate_key_pair(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    CRYS_RSA_KG_GenerateKeyPair(e, e_size, key_size, priv_key, pub_key, gen_data)

#define cc_rsa_generate_key_pair_crt(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    CRYS_RSA_KG_GenerateKeyPairCRT(e, e_size, key_size, priv_key, pub_key, gen_data)

#define cc_rsa_schemes_encrypt(rnd_ctx, pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version) \
    _DX_RSA_SCHEMES_Encrypt(pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version)

#define cc_ecc_generate_key_pair(rnd_ctx, domain_id, priv_key, pub_key, tmp_data, fis_ctx) \
    CRYS_ECPKI_GenKeyPair(domain_id, priv_key, pub_key, tmp_data)

#define cc_ecc_sign(rnd_ctx, user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len) \
    CRYS_ECDSA_Sign(user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len)

#define cc_dh_generate_pub_priv(rnd_ctx, generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, priv_key_len, pub_key, pub_key_len) \
    _DX_DH_GeneratePubPrv(generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, (uint16_t *)priv_key_len, pub_key, (uint16_t *)pub_key_len)

void set_secs_suspend_flag(void);
int32_t dxcc_power_on(void);
int32_t dxcc_power_off(void);
int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv);
int32_t dxcc_aes_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

dx_rand_ctx_t *get_rnd_context_ptr(void);
dx_rand_work_buf_t *get_rnd_workbuff_ptr(void);
int32_t read_entropy_data(void *buffer, size_t size);

#endif
