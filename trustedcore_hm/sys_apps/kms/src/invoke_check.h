/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: check for invoke
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-14
 */
#ifndef KMS_INVOKE_CHECK_H
#define KMS_INVOKE_CHECK_H
#include "tee_internal_api.h"
#include "invoke.h"
bool auth_vkms(void);
TEE_Result permission_check(uint32_t cmd_id);

int32_t kms_cmd_create_key_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iiio_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iion_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iiio_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iiii_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_begin_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_update_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_finish_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_random_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iinn_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_abort_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
int32_t kms_cmd_iiin_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
#endif
