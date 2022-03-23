/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto ecdsa header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_ECDSA_H
#define __KM_CRYPTO_ECDSA_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"

keymaster_error_t operation_ec_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size);
keymaster_error_t operation_ec_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_data_size,
    uint8_t *out_data, uint32_t *out_data_size);
void do_hash_update_for_sign_verify(key_auth *key_node, TEE_OperationHandle digest_contextid_ptr);

keymaster_error_t km_ec_begin(const keymaster_key_param_set_t *params_enforced, const keyblob_head *key_blob,
    key_auth *key_node, const struct kb_crypto_factors *factors);

int32_t proc_asymmetric_hash_update(key_auth *key_node, TEE_OperationHandle operation, uint8_t **data_update,
    uint32_t *data_update_len, uint32_t hash_len, uint8_t *datain_ptr, uint32_t data_size);

keymaster_error_t asymmetric_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size);

/* format ecdsa gp sign data to ASN.1, used for sw or openssl verify */
int32_t ec_sig_asn1_format(uint8_t *in, uint32_t *in_len, uint32_t in_buf_len);
keymaster_error_t ec_sign_verify(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *digest, uint32_t digest_len,
                                 uint8_t *signature, uint32_t *signature_len);
keymaster_error_t operation_ec_begin(key_auth * const key_node, const uint32_t key_size,
    const keymaster_blob_t *keymaterial, const uint32_t version, const keymaster_blob_t * const app_id);
#endif
