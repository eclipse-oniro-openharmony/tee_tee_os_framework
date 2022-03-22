/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto aes header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_AES_H
#define __KM_CRYPTO_AES_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"
keymaster_error_t proc_aes_gcm_for_operation_update(key_auth *key_node,
    const keymaster_key_param_set_t *params_enforced, uint8_t *in_data, uint32_t in_size,
    uint8_t *out_data, uint32_t *out_size);
keymaster_error_t proc_aes_gcm_with_no_force_for_operation_finish(key_auth *key_node,
    const keymaster_key_param_set_t *params_enforced, uint8_t *out_data, uint32_t *out_size);

keymaster_error_t km_aes_begin(key_auth *key_node, keymaster_blob_t *iv, keymaster_blob_t *key);

keymaster_error_t km_aes_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                uint32_t *out_size);
keymaster_error_t km_aes_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                uint32_t *out_size, int force);
#endif
