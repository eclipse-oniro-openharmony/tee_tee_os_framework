/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: provide log function.
 * Create: 2020/12/21
 */
#include <securec.h>
#include <stdarg.h>
#include <tee_log.h>

#define LOG_BUFFER_MAX_LEN  250

void seplat_external_log(const char *fmt, ...)
{
    int len;
    char log_temp[LOG_BUFFER_MAX_LEN] = {0};
    va_list vl;

    va_start(vl, fmt);
    len = vsnprintf_s(log_temp, LOG_BUFFER_MAX_LEN, LOG_BUFFER_MAX_LEN - 1, fmt, vl);
    va_end(vl);
    if (len < 0)
        return;

    tloge("%s", log_temp);
}
