/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto rsa header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_RSA_H
#define __KM_CRYPTO_RSA_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"
TEE_Result pack_rsa_key_for_soft_rsa(uint8_t *e, uint32_t e_len, uint8_t *n, uint32_t n_len, uint8_t *d,
    uint32_t d_len, uint8_t *P, uint32_t p_len, uint8_t *q, uint32_t q_len, uint8_t *dp, uint32_t dp_len, uint8_t *dq,
    uint32_t dq_len, uint8_t *qinv, uint32_t qinv_len, uint8_t *msg_buf, uint32_t msg_size);

keymaster_error_t preproc_for_rsa_sign_verify(uint32_t key_size_bytes, keymaster_purpose_t purpose,
                                              keymaster_padding_t padding, keymaster_digest_t digest_mode,
                                              uint32_t *digest_len);

keymaster_error_t operation_rsa_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size);

keymaster_error_t proc_rsa_operation_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
    uint8_t *out_data, uint32_t *out_size, int force);

keymaster_error_t km_rsa_begin(const keymaster_key_param_set_t *params_enforced, keyblob_head *key_blob,
    key_auth *key_node, const struct kb_crypto_factors *factors);

int32_t proc_asymmetric_hash_update(key_auth *key_node, TEE_OperationHandle operation, uint8_t **data_update,
    uint32_t *data_update_len, uint32_t hash_len, uint8_t *datain_ptr, uint32_t data_size);

keymaster_error_t asymmetric_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size);
#endif
