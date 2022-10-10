/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: register or unregister permission to ssa
 * Create: 2022-03-11
 */
#ifndef REGISTER_SSA_PERM_H
#define REGISTER_SSA_PERM_H

#include <tee_defines.h>
#include "permission_service.h"

void register_self_to_ssa(uint32_t task_id, uint32_t msg_id);
#endif
