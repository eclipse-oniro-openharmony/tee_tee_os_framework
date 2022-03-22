/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_GP_API_ADAPT_UTIL_H
#define KMS_GP_API_ADAPT_UTIL_H
#include <string.h>
#include <openssl/bn.h>
#include "kms_pub_def.h"
#include "gp_api_adaptation.h"

#define ENTLA_LEN                    2
#define BYTE_MAX                     256
#define BYTE_TO_BIT                  8
#define SM2_ZA_DATA_MAX_LEN          512
#define DEIGST_MAX_LEN               32
#define ED25519_PUB_KEY_ATTR_LEN     1
#define RSA_PUB_KEY_ATTR_LEN         2
#define ECDSA_PUB_KEY_ATTR_LEN       3

#define GP_CRT_MODE 1
#define GP_NOCRT_MODE 0
struct rsa_key_pair_bignum {
    BIGNUM *bn_n;
    BIGNUM *bn_e;
    BIGNUM *bn_d;
    BIGNUM *bn_p;
    BIGNUM *bn_q;
    BIGNUM *bn_dp;
    BIGNUM *bn_dq;
    BIGNUM *bn_qinv;
};

uint32_t key_type_kms_to_gp(uint32_t kms_key_type);
uint32_t alg_type_kms_to_gp(uint32_t kms_alg_type, uint32_t hash_type, uint32_t pad_mod);
uint32_t mod_kms_to_gp(uint32_t kms_mod);
uint32_t get_ecc_cur(uint32_t key_type, uint32_t key_size);
bool check_is_rsa_alg(uint32_t alg);
TEE_Result digest_for_sign_data(struct gp_key_opera_input *koi, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result init_key_opera_input(struct gp_key_opera_input *koi, const struct kms_buffer_data *key_blob,
    const struct kms_buffer_data *param_set, uint32_t kms_mod);
TEE_Result digest(uint32_t alg_type, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result get_sm2_za(TEE_ObjectHandle key_obj, struct kms_buffer_data *digest_data);
TEE_Result sm2_alloc_add_za_data(uint32_t alg_type, TEE_ObjectHandle key_obj, struct kms_buffer_data *in_data);
void sm2_free_alloc_in_data(uint32_t alg_type, struct kms_buffer_data *in_data);
TEE_Result import_symmetry_key(const struct kms_buffer_data *in_key, TEE_ObjectHandle keyobj);
TEE_Result export_symmetry_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_key);
TEE_Result export_rsa_public_key(TEE_ObjectHandle rsa_keyobj, struct kms_buffer_data *out_pub_key);
TEE_Result import_rsa_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle rsa_keyobj);
TEE_Result export_ecdsa_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key);
TEE_Result import_ecdsa_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle keyobj);
TEE_Result export_sm2_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key);
TEE_Result export_ed25519_public_key(TEE_ObjectHandle keyobj, struct kms_buffer_data *out_pub_key);
TEE_Result import_ed25519_public_key(const struct kms_buffer_data *in_pub_key, TEE_ObjectHandle keyobj);
TEE_Result import_rsa_keypair_pkcs1(const struct kms_buffer_data *in_key, TEE_ObjectHandle rsa_keyobj);
TEE_Result crypto_rsa(TEE_OperationHandle crypto_oper, struct gp_key_opera_input *koi, bool is_finish);
TEE_Result sm2_begin(struct gp_key_opera_input *koi);
TEE_Result sm2_digest(uint32_t alg_type, struct gp_key_opera_input *koi, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
#endif
