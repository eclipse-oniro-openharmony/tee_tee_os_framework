/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: teecall policy after delete public teecalls.
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */

#ifndef CT_TEECALL_POLICY_H
#define CT_TEECALL_POLICY_H

static const cap_teecall_t g_teecall_cap[AC_SID_NUM] = {
    /* builtin end */
#ifdef DEF_ENG
    [AC_ARRAY_IDX(TEE_SERVICE_ECHO)]           = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(TEE_SERVICE_UT)]             = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(HM_TEEOS_TEST)]              = { TEECALL_ALL_GROUP_PERMISSION },
    [AC_ARRAY_IDX(TEE_SERVICE_KERNELMEMUSAGE)] = { TEECALL_ALL_GROUP_PERMISSION },
#endif
};

#include "public_teecall.h"

#endif
