/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: interface declaration for ssa task adaptor
 * Author: l00238133
 * Create: 2019-10-28
 */

#ifndef GTASK_TASK_SSA_ADAPTOR_H
#define GTASK_TASK_SSA_ADAPTOR_H

#include "task_adaptor.h"

struct task_adaptor_info *register_task_ssa(void);
void task_ssa_load_manage_info(void);

#endif
