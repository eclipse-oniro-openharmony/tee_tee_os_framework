/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto by soft engine header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_SW_ENGINE_H
#define __KM_CRYPTO_SW_ENGINE_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"

TEE_Result pack_rsa_key_for_soft_rsa(uint8_t *e, uint32_t e_len, uint8_t *n, uint32_t n_len, uint8_t *d,
    uint32_t d_len, uint8_t *P, uint32_t p_len, uint8_t *q, uint32_t q_len, uint8_t *dp, uint32_t dp_len, uint8_t *dq,
    uint32_t dq_len, uint8_t *qinv, uint32_t qinv_len, uint8_t *msg_buf, uint32_t msg_size);
keymaster_error_t soft_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *digest,
                                       uint32_t digest_len, uint8_t *signature, uint32_t *signature_len);

keymaster_error_t oaep_pad_for_rsa_enc_dec(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *src_data,
                                           uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len, int force);

keymaster_error_t proc_digest_none_or_md5_for_ec_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len);
keymaster_error_t proc_digest_none_or_md5_for_ec_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, const uint32_t *signature_len);

uint32_t soft_rsa_begin(TEE_ObjectHandle key, key_auth *key_node);

bool use_soft_engine(const key_auth *key_node);

#endif
