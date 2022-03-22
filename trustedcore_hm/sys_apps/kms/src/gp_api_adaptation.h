/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_GP_API_ADAPTATION_H
#define KMS_GP_API_ADAPTATION_H
#include <string.h>
#include "tee_internal_api.h"
#include "kms_pub_def.h"
#include "tee_crypto_api.h"

#define BUF_OR_VALUE_MOVEBIT 2
#define IF_ZERO_MOVEBIT 31
#define object_attr_type(attr_id) (((attr_id) << BUF_OR_VALUE_MOVEBIT) >> IF_ZERO_MOVEBIT)
#define OBJECT_ATTR_BUFFER 0
#define GP_MAX_KEY_BUFFER 4096
#define GCM_TAG_MAX_LEN 128
#define GCM_TAG_MIN_LEN 96
#define DERIVER_FACTOR_MAX_LEN 256
#define KEYBLOB_CRYPTO_KEY_LEN 32
#define KEYBLOB_CRYPTO_KEY_SIZE 256
#define KEYBLOB_MAC_KEY_SIZE 256
#define GP_KEY_RESERVE_NUMBER 10
#define RSA_MAX_CRYPTO_DATA_LEN 512
#define RSA_MIN_SECURE_KEY_LEN 2048
#define ECDSA_MIN_SECURE_KEY_LEN 224
#define GCM_V1 1
#define GCM_V2 2
struct gp_key_opera_input {
    uint32_t alg_type;
    uint32_t key_size;
    uint32_t mode;
    uint32_t hash_type;
    uint32_t gcm_tag_len;
    TEE_ObjectHandle key_obj;
    TEE_OperationHandle crypto_oper;
    const struct kms_buffer_data *in_data;
    struct kms_buffer_data *out_data;
    struct kms_buffer_data iv;
    struct kms_buffer_data cache_data;
    struct kms_buffer_data aes_gcm_aad_data;
    uint32_t alg_version;
};

struct gp_key_base_info {
    uint32_t key_type;
    uint32_t key_size;
    uint32_t version;
    uint8_t iv[FIX_IV_LEN];
    uint32_t reserve[GP_KEY_RESERVE_NUMBER];
};
#define alg_hash_pad_index(alg, hash, pad) (((alg) << BYTE_TO_BIT) | ((hash) << HASH_TYPE_MOVE) | (pad))

#define INDEX_KMS_25519                                                             \
    { alg_hash_pad_index(KMS_ALG_ED25519, 0, 0), TEE_ALG_ED25519 }

#define INDEX_KMS_RSA                                                                                                \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_MD5, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_MD5 },         \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA1, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 },       \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA224, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 },   \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA256, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 },   \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA384, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 },   \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA512, KMS_PAD_RSA_PKCS1_SIGN), TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 },   \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA1, KMS_PAD_RSA_PSS_SIGN), TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 },     \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA224, KMS_PAD_RSA_PSS_SIGN), TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA256, KMS_PAD_RSA_PSS_SIGN), TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA384, KMS_PAD_RSA_PSS_SIGN), TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA512, KMS_PAD_RSA_PSS_SIGN), TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, 0, KMS_PAD_PKCS5), TEE_ALG_RSAES_PKCS1_V1_5 },     \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA1, KMS_PAD_RSA_OAEP), TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 },     \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA224, KMS_PAD_RSA_OAEP), TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA256, KMS_PAD_RSA_OAEP), TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA384, KMS_PAD_RSA_OAEP), TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 }, \
    { alg_hash_pad_index(KMS_ALG_RSA, KMS_HASH_SHA512, KMS_PAD_RSA_OAEP), TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 }

#define INDEX_KMS_ECDSA                                                                  \
    { alg_hash_pad_index(KMS_ALG_ECDSA, KMS_HASH_SHA1, 0), TEE_ALG_ECDSA_SHA1 },         \
    { alg_hash_pad_index(KMS_ALG_ECDSA, KMS_HASH_SHA224, 0), TEE_ALG_ECDSA_SHA224 },     \
    { alg_hash_pad_index(KMS_ALG_ECDSA, KMS_HASH_SHA256, 0), TEE_ALG_ECDSA_SHA256 },     \
    { alg_hash_pad_index(KMS_ALG_ECDSA, KMS_HASH_SHA384, 0), TEE_ALG_ECDSA_SHA384 },     \
    { alg_hash_pad_index(KMS_ALG_ECDSA, KMS_HASH_SHA512, 0), TEE_ALG_ECDSA_SHA512 }

#define INDEX_KMS_MAC                                                                \
    { alg_hash_pad_index(KMS_ALG_MAC, KMS_HASH_SHA256, 0), TEE_ALG_HMAC_SHA256 },    \
    { alg_hash_pad_index(KMS_ALG_SIP_HASH, 0, 0), TEE_ALG_SIP_HASH }

#define INDEX_KMS_AES                                                                \
    { alg_hash_pad_index(KMS_ALG_AES_ECB, 0, 0), TEE_ALG_AES_ECB_PKCS5 },             \
    { alg_hash_pad_index(KMS_ALG_AES_ECB, 0, KMS_PAD_PKCS5), TEE_ALG_AES_ECB_PKCS5 }, \
    { alg_hash_pad_index(KMS_ALG_AES_ECB, 0, KMS_PAD_NONE), TEE_ALG_AES_ECB_NOPAD },  \
    { alg_hash_pad_index(KMS_ALG_AES_CBC, 0, 0), TEE_ALG_AES_CBC_PKCS5 },             \
    { alg_hash_pad_index(KMS_ALG_AES_CBC, 0, KMS_PAD_PKCS5), TEE_ALG_AES_CBC_PKCS5 }, \
    { alg_hash_pad_index(KMS_ALG_AES_CBC, 0, KMS_PAD_NONE), TEE_ALG_AES_CBC_NOPAD },  \
    { alg_hash_pad_index(KMS_ALG_AES_GCM, 0, 0), TEE_ALG_AES_GCM },                   \
    { alg_hash_pad_index(KMS_ALG_AES_GCM_V2, 0, 0), TEE_ALG_AES_GCM },                   \
    { alg_hash_pad_index(KMS_ALG_AES_CMAC, 0, 0), TEE_ALG_AES_CMAC }

#define INDEX_KMS_ALG_HASH                                       \
    { alg_hash_pad_index(KMS_ALG_MD5, 0, 0), TEE_ALG_MD5 },       \
    { alg_hash_pad_index(KMS_ALG_SHA1, 0, 0), TEE_ALG_SHA1 },     \
    { alg_hash_pad_index(KMS_ALG_SHA224, 0, 0), TEE_ALG_SHA224 }, \
    { alg_hash_pad_index(KMS_ALG_SHA256, 0, 0), TEE_ALG_SHA256 }, \
    { alg_hash_pad_index(KMS_ALG_SHA384, 0, 0), TEE_ALG_SHA384 }, \
    { alg_hash_pad_index(KMS_ALG_SHA512, 0, 0), TEE_ALG_SHA512 }

#define INDEX_KMS_HASH_TYPE                                       \
    { alg_hash_pad_index(0, KMS_HASH_MD5, 0), TEE_ALG_MD5 },       \
    { alg_hash_pad_index(0, KMS_HASH_SHA1, 0), TEE_ALG_SHA1 },     \
    { alg_hash_pad_index(0, KMS_HASH_SHA224, 0), TEE_ALG_SHA224 }, \
    { alg_hash_pad_index(0, KMS_HASH_SHA256, 0), TEE_ALG_SHA256 }, \
    { alg_hash_pad_index(0, KMS_HASH_SHA384, 0), TEE_ALG_SHA384 }, \
    { alg_hash_pad_index(0, KMS_HASH_SHA512, 0), TEE_ALG_SHA512 }

#define INDEX_KMS_SM                                                                    \
    { alg_hash_pad_index(KMS_ALG_SM2_DSA_SM3, KMS_HASH_SM3, 0), TEE_ALG_SM2_DSA_SM3 }, \
    { alg_hash_pad_index(KMS_ALG_SM3, 0, 0), TEE_ALG_SM3 },                             \
    { alg_hash_pad_index(KMS_ALG_SM4_ECB, 0, KMS_PAD_NONE), TEE_ALG_SM4_ECB_NOPAD },    \
    { alg_hash_pad_index(KMS_ALG_SM4_CBC, 0, KMS_PAD_NONE), TEE_ALG_SM4_CBC_NOPAD },    \
    { alg_hash_pad_index(KMS_ALG_SM4_CTR, 0, 0), TEE_ALG_SM4_CTR },                     \
    { alg_hash_pad_index(KMS_ALG_SM4_GCM, 0, 0), TEE_ALG_SM4_GCM },                     \
    { alg_hash_pad_index(0, KMS_HASH_SM3, 0), TEE_ALG_SM3 }

/* gp_api_daapt inner interface */
TEE_Result init_key_opera_input(struct gp_key_opera_input *koi, const struct kms_buffer_data *key_blob,
    const struct kms_buffer_data *param_set, uint32_t kms_mod);
uint32_t alg_type_kms_to_gp(uint32_t kms_alg_type, uint32_t hash_type, uint32_t pad_mod);
uint32_t mod_kms_to_gp(uint32_t kms_mod);
TEE_Result sign_verify(struct gp_key_opera_input *koi);
TEE_Result crypto_gcm_final(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi);
/* for crypto_operation */
TEE_Result gp_create_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob);
TEE_Result gp_crypto(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result gp_digest(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result gp_sign_verify(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result gp_mac_generate(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result gp_begin(const struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct kms_buffer_data *opt_handle);
TEE_Result gp_update(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result gp_finish(const struct kms_buffer_data *opt_handle, uint32_t kms_mod,
    const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result gp_import_key(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_key,
    struct kms_buffer_data *key_blob);
TEE_Result key_blob_mac(struct kms_buffer_data *derived_factor, struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result key_blob_crypto(const struct kms_buffer_data *key_blob, uint32_t tee_mode, struct kms_buffer_data *out_data);
void gp_key_opera_free(struct gp_key_opera_input *koi);
void gp_abort(const struct kms_buffer_data *opt_handle);
TEE_Result gp_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *out_key,
    struct kms_buffer_data *key_blob);
TEE_Result gp_kdf_load_key(const struct kms_buffer_data *param_set, TEE_ObjectHandle *key_obj,
    struct kms_buffer_data *key_blob);
bool is_gcm_mode(uint32_t alg_type);
#endif
