/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc driver adapt defines
 * Create: 2020-06-18
 */
#ifndef CC_DRIVER_ADAPT_H
#define CC_DRIVER_ADAPT_H

#include "cc_hash.h"
#include "cc_lib.h"
#include "cc_hmac.h"
#include "cc_aes.h"
#include "cc_des.h"
#include "cc_aesccm.h"
#include "cc_rsa_types.h"
#include "cc_rsa_kg.h"
#include "cc_rsa_build.h"
#include "cc_rsa_prim.h"
#include "cc_rsa_schemes.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_kg.h"
#include "cc_ecpki_build.h"
#include "cc_ecpki_ecdsa.h"
#include "cc_ecpki_dh.h"
#include "cc_dh.h"
#include "cc_util_oem_asset.h"
#if (TRUSTEDCORE_PLATFORM_CHOOSE != WITH_BALONG_PLATFORM)
#include "cc_power.h"
#endif
#include "cc_rnd.h"
#include "cc_ecpki_domain.h"
#include "cc_driver_hal.h"
#include "crypto_driver_adaptor.h"

#define DX_DES_KEY_SIZE_IN_BYTES CC_DES_KEY_SIZE_IN_BYTES
#define DX_RSA_CRT CC_RSA_Crt
#define DX_RSA_NO_CRT CC_RSA_NoCrt
#define DX_PKCS1_VER15 CC_PKCS1_VER15
#define DX_EC_POINT_UNCOMPRESSED CC_EC_PointUncompressed
#define DX_EC_MAX_PUBLIC_KEY_LEN  (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 2 * sizeof(uint32_t) + 1)
#define DX_CHECK_POINTERS_SIZES_ONLY CheckPointersAndSizesOnly
#define DX_DH_PKCS3_MODE CC_DH_PKCS3_mode

struct hash_ctx_t {
    int32_t hash_mode;
    CCHashUserContext_t ctx;
};

struct hmac_ctx_t {
    int32_t hash_mode;
    CCHmacUserContext_t ctx;
};

struct cipher_ctx_t {
    uint32_t alg_type;
    union {
        CCAesUserContext_t aes;
        CCDesUserContext_t des;
    } ctx;
};

typedef enum {
    UTIL_USER_KEY        = 0,
    UTIL_ROOT_KEY        = 1,
    UTIL_SESSION_KEY     = 2,
    UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} UtilKeyType_t;
#include "cc_derivekey.h"
typedef CCRndContext_t dx_rand_ctx_t;
typedef CCRndWorkBuff_t dx_rand_work_buf_t;
typedef CCHashResultBuf_t hash_result_buf_t;
typedef CCAesCcmUserContext_t aes_ccm_ctx_t;
typedef CCDesIv_t des_iv_t;
typedef CCDesKey_t des_key_t;
typedef CCAesCcmKey_t aes_ccm_key_t;
typedef CCAesCcmMacRes_t aes_ccm_mac_res_t;
typedef CCRsaUserPrivKey_t dx_rsa_user_priv_key_t;
typedef CCRsaPrivKey_t dx_rsa_priv_key_t;
typedef CCRsaPrivUserContext_t dx_rsa_priv_user_ctx_t;
typedef CCRsaUserPubKey_t dx_rsa_user_pub_key_t;
typedef CCRsaPubUserContext_t dx_rsa_pub_user_ctx_t;
typedef CCRsaKgData_t dx_rsa_kg_data_t;
typedef CCRsaPrimeData_t dx_rsa_prime_data_t;
typedef CCEcpkiUserPublKey_t dx_ecc_user_pub_key_t;
typedef CCEcpkiPublKey_t dx_ecc_pub_key_t;
typedef CCEcpkiUserPrivKey_t dx_ecc_user_priv_key_t;
typedef CCEcpkiPrivKey_t dx_ecc_priv_key_t;
typedef CCEcpkiKgTempData_t dx_ecc_kg_temp_data_t;
typedef CCEcdsaSignUserContext_t dx_ecc_sign_user_ctx_t;
typedef CCEcpkiBuildTempData_t dx_ecc_build_temp_data_t;
typedef CCEcdsaVerifyUserContext_t dx_ecc_verify_user_ctx_t;
typedef CCEcdhTempData_t dx_ecdh_temp_data_t;
typedef CCDhUserPubKey_t dx_dh_user_pub_key_t;
typedef CCDhPrimeData_t dx_dh_prime_data_t;

#define GET_DX_EC_KEY_DOMAINID(key) ((key)->domain.DomainID)

struct alg_to_hash_mode_len_t {
    uint32_t alg_type;
    int32_t hash_mode;
    uint32_t hash_len;
};
static const struct alg_to_hash_mode_len_t g_hash_mode_len[] = {
    { CRYPTO_TYPE_DIGEST_MD5,    CC_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_DIGEST_SHA1,   CC_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_DIGEST_SHA224, CC_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_DIGEST_SHA256, CC_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_DIGEST_SHA384, CC_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_DIGEST_SHA512, CC_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_HMAC_MD5,      CC_HASH_MD5_mode,                MD5_LEN },
    { CRYPTO_TYPE_HMAC_SHA1,     CC_HASH_SHA1_mode,               SHA1_LEN },
    { CRYPTO_TYPE_HMAC_SHA224,   CC_HASH_SHA224_mode,             SHA224_LEN },
    { CRYPTO_TYPE_HMAC_SHA256,   CC_HASH_SHA256_mode,             SHA256_LEN },
    { CRYPTO_TYPE_HMAC_SHA384,   CC_HASH_SHA384_mode,             SHA384_LEN },
    { CRYPTO_TYPE_HMAC_SHA512,   CC_HASH_SHA512_mode,             SHA512_LEN },
    { CRYPTO_TYPE_ECDSA_SHA1,    CC_ECPKI_AFTER_HASH_SHA1_mode,   SHA1_LEN },
    { CRYPTO_TYPE_ECDSA_SHA224,  CC_ECPKI_AFTER_HASH_SHA224_mode, SHA224_LEN },
    { CRYPTO_TYPE_ECDSA_SHA256,  CC_ECPKI_AFTER_HASH_SHA256_mode, SHA256_LEN },
    { CRYPTO_TYPE_ECDSA_SHA384,  CC_ECPKI_AFTER_HASH_SHA384_mode, SHA384_LEN },
    { CRYPTO_TYPE_ECDSA_SHA521,  CC_ECPKI_AFTER_HASH_SHA512_mode, SHA512_LEN },
};

struct alg_to_cipher_mode_t {
    uint32_t alg_type;
    uint32_t drv_mode;
};
static const struct alg_to_cipher_mode_t g_cipher_mode[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,      CC_AES_MODE_ECB },
    { CRYPTO_TYPE_AES_CBC_NOPAD,      CC_AES_MODE_CBC },
    { CRYPTO_TYPE_AES_CTR,            CC_AES_MODE_CTR },
    { CRYPTO_TYPE_AES_CTS,            CC_AES_MODE_CBC_CTS },
    { CRYPTO_TYPE_AES_XTS,            CC_AES_MODE_XTS },
    { CRYPTO_TYPE_AES_CMAC,           CC_AES_MODE_CMAC },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,  CC_AES_MODE_CBC_MAC },
    { CRYPTO_TYPE_DES_ECB_NOPAD,      CC_DES_ECB_mode },
    { CRYPTO_TYPE_DES_CBC_NOPAD,      CC_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,     CC_DES_ECB_mode },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,     CC_DES_CBC_mode },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,  CC_DES_CBC_mode },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD, CC_DES_CBC_mode },
};

struct key_size_to_key_id_t {
    uint32_t key_size;
    int32_t key_id;
};
static const struct key_size_to_key_id_t g_key_size_id[] = {
    { AES_KEY_16_BYTES, CC_AES_Key128BitSize },
    { AES_KEY_24_BYTES, CC_AES_Key192BitSize },
    { AES_KEY_32_BYTES, CC_AES_Key256BitSize },
    { AES_KEY_64_BYTES, CC_AES_Key512BitSize },
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
    CCRsaHashOpMode_t hash_mode;
    CCPkcs1Mgf_t pkcs1_mgf;
    CCPkcs1Version_t pkcs1_version;
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
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5,        { CC_RSA_After_MD5_mode,    CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1,       { CC_RSA_After_SHA1_mode,   CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224,     { CC_RSA_After_SHA224_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256,     { CC_RSA_After_SHA256_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384,     { CC_RSA_After_SHA384_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512,     { CC_RSA_After_SHA512_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,    { CC_RSA_After_MD5_mode,    CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,   { CC_RSA_After_SHA1_mode,   CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, { CC_RSA_After_SHA224_mode, CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, { CC_RSA_After_SHA256_mode, CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, { CC_RSA_After_SHA384_mode, CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, { CC_RSA_After_SHA512_mode, CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
};

struct rsa_alg_to_ency_info_t {
    uint32_t alg_type;
    struct cc_rsa_info_t ency_info;
};

static const struct rsa_alg_to_ency_info_t g_rsa_alg_to_ency_info[] = {
    { CRYPTO_TYPE_RSA_NO_PAD,                   { CC_RSA_HASH_NO_HASH_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_V1_5,             { CC_RSA_HASH_NO_HASH_mode, CC_PKCS1_NO_MGF, CC_PKCS1_VER15 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1,   { CC_RSA_HASH_SHA1_mode,    CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224, { CC_RSA_HASH_SHA224_mode,  CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256, { CC_RSA_HASH_SHA256_mode,  CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384, { CC_RSA_HASH_SHA384_mode,  CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
    { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512, { CC_RSA_HASH_SHA512_mode,  CC_PKCS1_MGF1,   CC_PKCS1_VER21 } },
};

struct ecc_curve_domain_t {
    uint32_t curve_id;
    int32_t domain_id;
    uint32_t key_size;
};

static const struct ecc_curve_domain_t g_ecc_curve_domain[] = {
    { ECC_CURVE_NIST_P192, CC_ECPKI_DomainID_secp192r1, ECC_192_KEY_SIZE },
    { ECC_CURVE_NIST_P224, CC_ECPKI_DomainID_secp224r1, ECC_224_KEY_SIZE },
    { ECC_CURVE_NIST_P256, CC_ECPKI_DomainID_secp256r1, ECC_256_KEY_SIZE },
    { ECC_CURVE_NIST_P384, CC_ECPKI_DomainID_secp384r1, ECC_384_KEY_SIZE },
    { ECC_CURVE_NIST_P521, CC_ECPKI_DomainID_secp521r1, ECC_521_KEY_SIZE },
};

#define cc_hash_init CC_HashInit
#define cc_hash_update CC_HashUpdate
#define cc_hash_finish CC_HashFinish

#define cc_hmac_init CC_HmacInit
#define cc_hmac_update CC_HmacUpdate
#define cc_hmac_finish CC_HmacFinish

#define cc_aes_block CC_AesBlock

#define cc_des_init CC_DesInit
#define cc_des_block CC_DesBlock

#define cc_aes_ccm_init CC_AesCcmInit
#define cc_aes_ccm_update_aad CC_AesCcmBlockAdata
#define cc_aes_ccm_update_data CC_AesCcmBlockTextData
#define cc_aes_ccm_finish CC_AesCcmFinish

#define cc_rsa_build_priv_key CC_RsaPrivKeyBuild
#define cc_rsa_build_priv_key_crt CC_RsaPrivKeyCrtBuild
#define cc_rsa_build_pub_key CC_RsaPubKeyBuild
#define cc_rsa_verify CC_RsaVerify
#define cc_rsa_get_pub_key CC_RsaPubKeyGet
#define cc_rsa_get_priv_key CC_RsaGetPrivKey
#define cc_rsa_get_priv_key_crt CC_RsaGetPrivKeyCRT
#define cc_rsa_prim_encrypt CC_RsaPrimEncrypt
#define cc_rsa_prim_decrypt CC_RsaPrimDecrypt
#define cc_rsa_schemes_decrypt CC_RsaSchemesDecrypt

#define cc_ecc_export_pub_key CC_EcpkiPubKeyExport
#define cc_ecc_verify CC_EcdsaVerify
#define cc_ecdh_svdp_dh CC_EcdhSvdpDh

#define cc_dh_get_secret_key dxcc_dh_get_secret_key_adaptr

#define cc_cmac_derive_key(user_key, data_in, data_in_size, mac_res) \
    UtilCmacDeriveKey(UTIL_ROOT_KEY, user_key, data_in, data_in_size, mac_res)

#define cc_lib_init(rnd_ctx, rnd_work_buf, is_fips, fips_ctx) \
    CC_LibInit(rnd_ctx, rnd_work_buf, is_fips, fips_ctx)

#define cc_rand_generate_vector(rnd_state, size, buffer) \
    CC_RndGenerateVector(rnd_state, size, buffer)

#define cc_rsa_sign(rnd_ctx, cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version) \
    CC_RsaSign(rnd_ctx, cc_ctx, priv_key, hash_mod, pkcs1_mgf, salt, \
    digest, digest_len, signature, signature_len, pkcs1_version)

#define cc_rsa_generate_key_pair(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    CC_RsaKgKeyPairGenerate(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx)

#define cc_rsa_generate_key_pair_crt(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx) \
    CC_RsaKgKeyPairCrtGenerate(rnd_ctx, e, e_size, key_size, priv_key, pub_key, gen_data, fips_ctx)

#define cc_rsa_schemes_encrypt(rnd_ctx, pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version) \
    CC_RsaSchemesEncrypt(rnd_ctx, pub_key, prime_data, hash_mode, l, l_len, pkcs1_mgf, \
    data_in, data_in_size, data_out, pkcs1_version)

#define cc_ecc_generate_key_pair(rnd_ctx, domain_id, priv_key, pub_key, tmp_data, fips_ctx) \
    CC_EcpkiKeyPairGenerate(rnd_ctx, CC_EcpkiGetEcDomain(domain_id), priv_key, pub_key, tmp_data, fips_ctx)

#define cc_ecc_build_priv_key(domain_id, priv_key, priv_key_len, user_priv_key) \
    CC_EcpkiPrivKeyBuild(CC_EcpkiGetEcDomain(domain_id), priv_key, priv_key_len, user_priv_key)

#define cc_ecc_build_pub_key(domain_id, pub_key, pub_key_len, check_mode, user_pub_key, tmp_data) \
    CC_EcpkiPublKeyBuildAndCheck(CC_EcpkiGetEcDomain(domain_id), pub_key, pub_key_len, check_mode, \
    user_pub_key, tmp_data)

#define cc_ecc_sign(rnd_ctx, user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len) \
    CC_EcdsaSign(rnd_ctx, user_ctx, priv_key, hash_mode, digest, digest_len, signature, signature_len)

#define cc_dh_generate_pub_priv(rnd_ctx, generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, priv_key_len, pub_key, pub_key_len) \
    CC_DhGeneratePubPrv(rnd_ctx, generator, generator_size, prime, prime_size, l, q, q_size, \
    dh_mode, tmp_key, tmp_data, priv_key, priv_key_len, pub_key, pub_key_len)

void set_secs_suspend_flag(void);
int32_t dxcc_power_on(void);
int32_t dxcc_power_off(void);
int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv);
int32_t dxcc_aes_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

dx_rand_ctx_t *get_rnd_context_ptr(void);
dx_rand_work_buf_t *get_rnd_workbuff_ptr(void);
uint32_t dxcc_dh_get_secret_key_adaptr(uint8_t *client_prvkey_ptr, size_t clientprv_keysize,
    uint8_t *server_pubkey_ptr, size_t serverpub_keysize, uint8_t *prime_ptr, size_t primesize,
    dx_dh_user_pub_key_t *tmp_pubkey_ptr, dx_dh_prime_data_t *tmpprime_data_ptr,
    uint8_t *secretKey_ptr, uint16_t *secret_keysize_ptr);
int32_t read_entropy_data(void *buffer, size_t size);
#endif
