/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto HMAC header
 * Create: 2020-11-09
 */
#ifndef __KM_CRYPTO_HMAC_H
#define __KM_CRYPTO_HMAC_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
#include "keymaster_defs.h"
#include "km_keynode.h"
#include "keyblob.h"

keymaster_error_t km_hmac_begin(key_auth *key_node, keymaster_blob_t *key);
keymaster_error_t hmac_get_object(uint32_t algorithm, uint32_t *object_type);

keymaster_error_t km_hmac_init(keymaster_blob_t *key, key_auth *key_node);

keymaster_error_t km_hmac_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size);

keymaster_error_t hmac_finish(const key_auth *key_node, const uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                              uint32_t *out_size, int force);
#endif
