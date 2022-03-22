/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto adaptor header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_ADAPTOR_H
#define __KM_CRYPTO_ADAPTOR_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"

int32_t ec_nist_curve2key_size(TEE_ECC_CURVE ecc_curv, uint32_t *key_size);
keymaster_ec_curve_t ec_nist_curve2kmcurve(TEE_ECC_CURVE ec_curve);
int32_t ec_keysize2nist_curve(uint32_t key_size, TEE_ECC_CURVE *ecc_curv);

int32_t km_ec_domain_id_to_keysize(keymaster_ec_curve_t domain, uint32_t *key_size);
keymaster_error_t get_sym_purpose(keymaster_purpose_t purpose, TEE_OperationMode *mode);
keymaster_error_t check_block_mode(keymaster_block_mode_t block_mode, uint32_t *mode);
keymaster_error_t get_aes_algorithm(keymaster_block_mode_t block_mode, keymaster_padding_t padding, uint32_t *alg);
keymaster_error_t hash_mode_to_size_bits(keymaster_digest_t digest, uint32_t *digest_len_bits);
keymaster_error_t get_ec_algorithm(const keymaster_digest_t digest, uint32_t *algorithm);
keymaster_error_t get_hmac_algorithm(const keymaster_digest_t digest, uint32_t *algorithm);
keymaster_error_t get_rsa_purpose(const keymaster_purpose_t purpose, TEE_OperationMode *mode);
keymaster_error_t get_rsa_algorithm(const keymaster_padding_t padding, const keymaster_digest_t digest,
    uint32_t *algorithm);
keymaster_error_t get_ec_pupose(const keymaster_purpose_t purpose, TEE_OperationMode *mode);
TEE_Result look_up_table(const keymaster_uint2uint *buff, uint32_t buff_len, uint32_t src, uint32_t *dst);
TEE_Result get_key_obj_type(keymaster_algorithm_t algorithm, keymaster_digest_t digest_mode,
    uint32_t *object_type);
TEE_Result get_key_object(keymaster_algorithm_t algorithm, uint32_t key_size,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_ObjectHandle *key_obj);
int32_t get_hash_block_size(keymaster_digest_t digest, uint32_t *block_size);
uint32_t keymaster_get_digest_hash(const uint32_t digest_mode);
int32_t km_hash_to_soft_hash(keymaster_digest_t digest, uint32_t *hash_function);
#endif
