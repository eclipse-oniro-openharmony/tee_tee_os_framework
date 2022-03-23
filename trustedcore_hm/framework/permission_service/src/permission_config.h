/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ta permission check function defines
 * Create: 2019-10-15
 */
#ifndef PERMISSION_CONFIG
#define PERMISSION_CONFIG

#include <tee_defines.h>

uint32_t get_rpmb_threshold(const TEE_UUID *uuid);
uint64_t get_rpmb_permission(const TEE_UUID *uuid);
bool check_tui_permission(const TEE_UUID *uuid);
bool check_sem_permission(const TEE_UUID *uuid);

#endif
