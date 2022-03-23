/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster command handles function
 * Create: 2020-11-09
 */
#ifndef  __KM_CMD_HANDLE_H
#define __KM_CMD_HANDLE_H
#include "cmd_params_check.h"
#include "crypto_wrapper.h"

TEE_Result km_configure(uint32_t param_types, const TEE_Param *params);
TEE_Result km_generate_key(uint32_t param_types, TEE_Param *params);
TEE_Result km_get_key_characteristics(uint32_t param_types, TEE_Param *params);
TEE_Result km_import_key(uint32_t param_types, TEE_Param *params);
TEE_Result km_export_key(uint32_t param_types, TEE_Param *params);
TEE_Result km_delete_key(uint32_t param_types, const TEE_Param *params);
TEE_Result km_delete_all_keys(void);
TEE_Result km_begin(uint32_t param_types, TEE_Param *params);
TEE_Result km_update(uint32_t param_types, TEE_Param *params);
TEE_Result km_finish(uint32_t param_types, TEE_Param *params);
TEE_Result km_abort(uint32_t param_types, const TEE_Param *params);
TEE_Result km_upgrade(uint32_t param_types, TEE_Param *params);
TEE_Result km_attest_key(uint32_t param_types, TEE_Param *params);
TEE_Result km_id_identifiers(uint32_t param_types, const TEE_Param *params, uint32_t cmd);
TEE_Result km_destroy_identifiers(uint32_t param_types, TEE_Param *params);
#endif