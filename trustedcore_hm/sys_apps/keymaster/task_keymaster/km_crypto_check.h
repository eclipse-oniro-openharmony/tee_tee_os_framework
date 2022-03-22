/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto check header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_CHECK_H
#define __KM_CRYPTO_CHECK_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"
TEE_Result check_gen_key_params(keymaster_algorithm_t algorithm, uint32_t key_size_bits,
    const keymaster_key_param_set_t *params_hw_enforced);
int32_t check_aes_keysize_bits(uint32_t key_size_bits);
int32_t check_algorithm_keysize(keymaster_algorithm_t algorithm, uint32_t key_size_bits);
keymaster_error_t check_ec_padding_digest_purpose(keymaster_padding_t *padding, keymaster_digest_t *digest,
    keymaster_purpose_t purpose, const keymaster_key_param_set_t *hw_enforced,
    const keymaster_key_param_set_t *params_enforced);
int32_t check_padding_for_rsa_enc_dec(keymaster_padding_t padding);
keymaster_error_t check_rsa_padding_params(keymaster_padding_t *padding,
    const keymaster_key_param_set_t *params_enforced, keymaster_purpose_t purpose,
    const keymaster_key_param_set_t *hw_enforced);
keymaster_error_t check_rsa_diagest_params(keymaster_padding_t padding, keymaster_purpose_t purpose,
    keymaster_digest_t *digest, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced);
int32_t check_purpose_for_rsa_enc_dec(keymaster_purpose_t purpose);
keymaster_error_t check_rsa_digest_is_valid(keymaster_padding_t padding, keymaster_digest_t digest);
keymaster_error_t check_rsa_digest_mode(keymaster_padding_t padding, keymaster_digest_t digest, uint32_t key_size);
keymaster_error_t check_hmc_tag_len(key_auth *key_node, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, uint32_t *tag_len);
keymaster_error_t check_operation_rsa_update(const key_auth *key_node, uint32_t in_size);
int32_t check_padding_for_rsa_sign_verify(keymaster_padding_t padding);

int32_t check_purpose_for_rsa_sign_verify(keymaster_purpose_t purpose);
keymaster_error_t check_gcm_tag_len(uint32_t block_mode, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, uint32_t *tag_len, uint32_t *min_tag_len);
TEE_Result check_hmac_key_params(keymaster_algorithm_t algorithm,
                                 const keymaster_key_param_set_t *params_hw_enforced);
keymaster_error_t check_aes_tag(keymaster_algorithm_t algorithm,
                                const keymaster_key_param_set_t *params_hw_enforced);
#endif
