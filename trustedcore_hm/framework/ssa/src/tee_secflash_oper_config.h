/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: secflash fs oper access check
 * Author: hemuyang1@huawei.com
 * Create: 2021-11-17
 */

#ifndef TEE_SECFLASH_OPER_CONFIG_H
#define TEE_SECFLASH_OPER_CONFIG_H

#include "tee_defines.h"

TEE_Result secflash_reset_permission_in_tbl(const TEE_UUID *uuid);
TEE_Result secflash_status_permission_in_tbl(const TEE_UUID *uuid);
TEE_Result secflash_get_ta_threshold_in_tbl(const TEE_UUID *uuid, uint32_t *ta_threshold);

#endif
