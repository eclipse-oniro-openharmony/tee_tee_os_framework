/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tee gmssl api implementation
 * Create: 2018-05-18
 */
#ifndef __TEE_GMSSL_API_H__
#define __TEE_GMSSL_API_H__

#include <tee_defines.h>
#include <ta_framework.h>
#include <crypto_driver_adaptor.h>
#include <crypto_syscall.h>

#define SM2_GROUP_NOSTANDARD   0x12
#define SM2_ENCRYPTED_LEN      200
#define SM2_INCREASE_MAX       110
#define SM2_INCREASE_MIN       106
#define SM2_SIGN_MAX           72
#define SM2_SIGN_MIN           70
#define SM2_DIGEST_LEN         32
#define SM2_KEYPAIR_ATTR_COUNT 4
#define SM2_KEY_SIZE_BIT       256
#define STR_TO_HEX             2
#define HEX_FLAG               16

int32_t sm3_digest_init(struct ctx_handle_t *ctx);

int32_t sm3_digest_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t sm3_digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t crypto_sm3_hash(const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm3_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key);

int32_t sm3_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t sm3_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t crypto_sm3_hmac(const struct symmerit_key_t *key, const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm2_sign_verify(const void *sm2_key, uint32_t mode, const struct memref_t *digest,
    struct memref_t *signature);

int32_t sm2_encrypt_decypt(const void *private_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv);

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t sm2_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key);

int32_t soft_copy_gmssl_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src);

void free_sm4_context(uint64_t *ctx);

int32_t gm_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param);

int32_t gm_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data);

int32_t gm_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int32_t gm_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out);

int32_t gm_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out);
#endif
