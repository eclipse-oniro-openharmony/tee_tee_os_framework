/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Local time function
 * Create: 2019-08-20
 */
#include "localtime.h"
#include <timer.h>

struct tm *localtime_internal(const time_t *t)
{
    static struct tm value;

    return __localtime_r(t, &value);
}
