/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: for global task unpack internal tasks.
 * Author: Zhangdeyao  zhangdeyao@huawei.com
 * Create: 2022-8-10
 */

#ifndef _TEE_INITLIB_H
#define _TEE_INITLIB_H
#include <ta_framework.h>
#include "gtask_core.h"
void load_dynamic_service(const struct service_struct *dead_srv);
void load_internal_task(const TEE_UUID *uuid);
#endif /* _TEE_INITLIB_H */
