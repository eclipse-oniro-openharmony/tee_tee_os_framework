/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ssa fs oper access check
 * Create: 2019.12.28
 */

#ifndef __SSA_TEE_FS_OPER_CONFIG_H
#define __SSA_TEE_FS_OPER_CONFIG_H

#include "tee_defines.h"

bool check_ta_access(const TEE_UUID *uuid);
bool check_ta_access_file_permission(const TEE_UUID *uuid, const char *file_name);

#endif
