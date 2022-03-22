/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest key check
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "keyblob.h"
#include "km_types.h"
#include "km_tag_operation.h"
#include "km_crypto_adaptor.h"
TEE_Result check_ec_keymaterial_header(const keymaster_blob_t *keymaterial_blob)
{
    const struct keymaterial_ecdsa_header *header = (struct keymaterial_ecdsa_header *)keymaterial_blob->data_addr;
    if (header->magic != KM_MAGIC_NUM) {
        tloge("magic is 0x%x, keymaterial is invalid\n", header->magic);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((keymaterial_blob->data_length - sizeof(*header)) < header->key_buff_len) {
        tloge("keymaterial_size is %u, keysize is %u, keymaterial is invalid\n", keymaterial_blob->data_length,
              header->key_buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result get_alg_keysize_from_paramsets(keymaster_algorithm_t *algorithm, uint32_t *key_size_bits,
    const keymaster_key_param_set_t *param_enforced)
{
    bool check_fail = (algorithm == NULL || key_size_bits == NULL || param_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* get algorithm from input param_enforced */
    if (get_key_param(KM_TAG_ALGORITHM, algorithm, param_enforced) != 0) {
        tloge("get_key_param of keymaster_algorithm_t failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* get keysize from input param_enforced */
    if (get_key_param(KM_TAG_KEY_SIZE, key_size_bits, param_enforced) != 0) {
        if (*algorithm == KM_ALGORITHM_EC) {
            /* ec key size may be deduced by ec curve */
            uint32_t ec_curve_value = 0;
            if (get_key_param(KM_TAG_EC_CURVE, &ec_curve_value, param_enforced) != 0) {
                /* must find ec curve while key size not found */
                tloge("get_key_param of ec_curve_value failed\n");
                return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }

            if (km_ec_domain_id_to_keysize((keymaster_ec_curve_t)ec_curve_value, key_size_bits) != 0) {
                tloge("get key_size from ec_curve failed\n");
                return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
            }
        } else {
            tloge("get key param of key_size failed\n");
            return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
    }
    return TEE_SUCCESS;
}