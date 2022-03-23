/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_H
#define __KM_CRYPTO_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"
int32_t hmac_with_key(uint8_t *key, const uint8_t *src, uint32_t src_size, uint8_t *dst, uint32_t dst_size);

keymaster_error_t triple_des_init(const keymaster_blob_t *iv, keymaster_blob_t *key, key_auth *key_node);
keymaster_error_t triple_des_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                    uint32_t *out_size);
keymaster_error_t triple_des_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                    uint32_t *out_size, int force);
int32_t do_sign_func(uint32_t *sig_out_len, uint8_t *hash_buf, uint8_t *out, const struct dev_key_t *dev_key);

keymaster_error_t km_hmac_begin(key_auth *key_node, keymaster_blob_t *key);
keymaster_error_t km_3des_begin(key_auth *key_node, keymaster_blob_t *key,
    const keymaster_blob_t *iv);

keymaster_error_t alloc_data_buff_for_operation_symmetric_begin(key_auth *key_node, uint32_t data_size);


int32_t proc_asymmetric_hash_update(key_auth *key_node, TEE_OperationHandle operation, uint8_t **data_update,
    uint32_t *data_update_len, uint32_t hash_len, uint8_t *datain_ptr, uint32_t data_size);
keymaster_error_t do_hash_for_sign_verify(key_auth *key_node);
keymaster_error_t asymmetric_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size);

int32_t asymmetric_hash_update(key_auth *key_node, uint8_t *datain_ptr, uint32_t data_size);
/* compare hash with buf in(SHA256) */
int32_t hash_compare(const uint8_t *buf, const uint32_t buf_len, const uint8_t *hash);
keymaster_error_t operation_update(uint64_t operation_handle, const keymaster_key_param_set_t *params_enforced,
                                   keymaster_blob_t *in_data, keymaster_blob_t *out_data);
keymaster_error_t operation_finish(uint64_t operation_handle, const keymaster_key_param_set_t *params_enforced,
                                   keymaster_blob_t *in_data, keymaster_blob_t *out_data, int force);
keymaster_error_t km_algorithm_begin(const keymaster_key_param_set_t *params_enforced, keyblob_head *key_blob,
                                     key_auth *key_node, const struct kb_crypto_factors *factors, TEE_Param *params);
TEE_Result init_key_obj(keymaster_algorithm_t km_alg, keymaster_digest_t digest, uint32_t key_size_bits,
    TEE_ObjectHandle *obj_handle, keymaster_blob_t *key);
TEE_Result init_key_operation(TEE_OperationHandle *op_handle, uint32_t alg, uint32_t gp_purpose, uint32_t key_size_bits,
    const TEE_ObjectHandle *key_obj);

int32_t get_kb_crypto_factors(const keymaster_key_param_set_t *params_blob,
    const keymaster_key_param_set_t *params_input, uint32_t version, const keymaster_blob_t *app_id,
    struct kb_crypto_factors *factors);
#endif
