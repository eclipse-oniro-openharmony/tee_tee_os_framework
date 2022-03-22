/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teecall policy after delete public teecalls.
 * Author: wangxiaochu  wangxiaochu@huawei.com
 * Create: 2020-10
 */

#ifndef MINI_TEECALL_POLICY_H
#define MINI_TEECALL_POLICY_H

static const cap_teecall_t g_teecall_cap[AC_SID_NUM] = {
#ifdef DEF_ENG
    [AC_ARRAY_IDX(TEE_SERVICE_ECHO)]           = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(TEE_SERVICE_UT)]             = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(HM_TEEOS_TEST)]              = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(TEE_SERVICE_KERNELMEMUSAGE)] = { TEECALL_ALL_GROUP_PERMISSION },
#endif
};

#include "public_teecall.h"

#endif