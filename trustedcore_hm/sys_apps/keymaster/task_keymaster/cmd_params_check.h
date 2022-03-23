/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster command param checks function
 * Create: 2020-11-09
 */
#ifndef __KM_CMD_PARAMS_CHECK_H
#define __KM_CMD_PARAMS_CHECK_H
#include "tee_internal_api.h"
#include "keymaster_defs.h"

TEE_Result km_generate_param_check(uint32_t param_types, const TEE_Param *params,
                                   keymaster_key_param_set_t **params_hw_enforced);

TEE_Result check_begin_param(uint32_t param_types, const TEE_Param *params,
                             keymaster_key_param_set_t **params_enforced);
TEE_Result km_store_verify_params_check(const TEE_Param *params, int flag);
TEE_Result km_upgrade_check(uint32_t param_types, const TEE_Param *params);
TEE_Result km_attest_key_check(uint32_t param_types, TEE_Param *params);
TEE_Result init_key_size(uint32_t *key_size, keymaster_algorithm_t algorithm,
    keymaster_key_param_set_t *params_hw_enforced);
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
TEE_Result check_policy_set(uint32_t param_types, const TEE_Param *params);
#endif
TEE_Result km_abort_params_check(uint32_t param_types, const TEE_Param *params);

TEE_Result check_update_params(uint32_t param_types, const TEE_Param *params,
    keymaster_key_param_set_t **params_enforced, keymaster_blob_t *in_data);
TEE_Result check_finish_params(uint32_t param_types, const TEE_Param *params,
    keymaster_key_param_set_t **params_enforced, keymaster_blob_t *final_data);
#endif