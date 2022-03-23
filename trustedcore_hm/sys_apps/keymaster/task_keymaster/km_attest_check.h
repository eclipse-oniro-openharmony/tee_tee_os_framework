/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest key check
 * Create: 2020-11-09
 */
#ifndef __KM_ATTEST_CHECK_H
#define __KM_ATTEST_CHECK_H
#include "tee_internal_api.h"
#include "keymaster_defs.h"

TEE_Result check_ec_keymaterial_header(const keymaster_blob_t *keymaterial_blob);
TEE_Result get_alg_keysize_from_paramsets(keymaster_algorithm_t *algorithm, uint32_t *key_size_bits,
    keymaster_key_param_set_t *param_enforced);
#endif