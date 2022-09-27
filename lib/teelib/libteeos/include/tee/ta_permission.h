/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: headfile for ta permission
 * Create: 2019-12-20
 */

#ifndef TA_PERMISSION_H
#define TA_PERMISSION_H

#include <tee_defines.h>
#include <uidgid.h>

int ta_permission_init(void);
TEE_Result get_ta_permission_wrapper(uid_t uid, uint64_t *permissions);

#endif
