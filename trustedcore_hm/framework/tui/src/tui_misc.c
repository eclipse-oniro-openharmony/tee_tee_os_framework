/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tui service whitelist.
 * Author: Tian Jianliang tianjianliang@huawei.com
 * Create: 2020-12-01
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
#ifdef CONFIG_DYNLINK
__attribute__((section(".magic"))) const char g_magic_string[] = "Dynamically linked.";
#endif

VISUAL void tee_task_entry(int32_t init_build)
{
    tlogi("tarunner load tui service");
    tee_task_entry_internal(init_build);
}

