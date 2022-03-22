/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: the misc function for tui task
 * Create: 2020-04-06
 */
#include "tui_misc.h"

#include <tee_log.h>

#define VISUAL __attribute__((visibility("default")))

bool tui_get_usermode(void)
{
#ifdef DEF_BUILDUSERMODE
    return true;
#else
    return false;
#endif
}
VISUAL void tee_task_entry(int32_t init_build)
{
    tlogi("taloader load tui service");
    tee_task_entry_internal(init_build);
}
