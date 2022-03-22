/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Local real time function
 * Create: 2019-08-20
 */
#include "localtime_r.h"
#include <hmlog.h>

struct tm *__localtime_r(const time_t *restrict t, struct tm *restrict value)
{
    struct tm *tmp = NULL;
#ifdef __LP64__
    /*
     * Reject time_t values whose year would overflow int because
     * __secs_to_zone cannot safely handle them.
     */
    if ((t != NULL) && ((*t < INT_MIN * MAX_SECONDS_PER_YEAR) || (*t > INT_MAX * MAX_SECONDS_PER_YEAR)))
        return NULL;
#endif

    if (t == NULL)
        return NULL;

    if (value == NULL) {
        hm_error("value is NULL\n");
        return NULL;
    }

    tmp = hm_localtime_r(t, value);
    if (tmp == NULL) {
        hm_error("localtime: get value is NULL\n");
        return NULL;
    }

    return value;
}
