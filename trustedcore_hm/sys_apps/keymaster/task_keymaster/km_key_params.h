/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key params operation header
 * Create: 2020-02-13
 */
#ifndef __KM_KEY_PARAMS_H
#define __KM_KEY_PARAMS_H

#include "tee_internal_api.h"
#include "keyblob.h"

int key_param_set_len_check(const keymaster_key_param_set_t *param_keymaster, uint32_t param_size);

TEE_Result km_get_key_params_check(uint32_t param_types, const TEE_Param *params,
                                   keymaster_key_param_set_t **params_enforced);
TEE_Result km_import_param_check(uint32_t param_types, const TEE_Param *params);
TEE_Result km_export_param_check(uint32_t param_types, const TEE_Param *params,
                                 keymaster_key_param_set_t **params_enforced);

int32_t check_enforce_info(uint32_t enforced_len, uint32_t hw_sw_size, uint32_t param_size,
    const keymaster_key_param_t *params_enforced, uint32_t *extend_buf_size);
int32_t key_param_set_check(const keymaster_key_param_set_t *param_keymaster, uint32_t param_size);

int32_t resort_key_characteristics(uint8_t *dst, const uint8_t *src, uint32_t size);
#endif