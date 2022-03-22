/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster cmd handle provision header
 * Create: 2020-11-09
 */
#ifndef __KM_CMD_HANDLE_PROVISION_H
#define __KM_CMD_HANDLE_PROVISION_H
#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "keyblob.h"
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
TEE_Result km_key_policy_set(uint32_t param_types, const TEE_Param *params);
#endif
TEE_Result km_store_kb(uint32_t param_types, TEE_Param *params);
TEE_Result km_verify_kb(uint32_t param_types, TEE_Param *params);

TEE_Result km_verify_attestationids_with_param(uint32_t param_types, const TEE_Param *params);
#endif