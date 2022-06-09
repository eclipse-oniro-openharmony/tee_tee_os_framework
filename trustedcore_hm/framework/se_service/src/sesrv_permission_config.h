/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Se service whitelist.
 * Create: 2019-12-28
 */
#ifndef SESRV_PERMISSION_CONFIG_H
#define SESRV_PERMISSION_CONFIG_H

#include "tee_defines.h"

TEE_Result se_service_check_msp_permission(const TEE_UUID *uuid);
bool is_msp_enable(void);
uint32_t get_vote_id(uint32_t reader_id, const TEE_UUID *uuid);

#endif
