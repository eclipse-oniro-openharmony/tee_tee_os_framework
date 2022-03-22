/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tui service whitelist.
 * Author: Tian Jianliang tianjianliang@huawei.com
 * Create: 2020-12-01
 */

#ifndef TASK_TUI_MISC_H
#define TASK_TUI_MISC_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <thp_afe.h>

bool tui_get_usermode(void);
void tee_task_entry_internal(int32_t init_build);

__attribute__((weak)) int32_t thp_init(void)
{
    return 0;
}

__attribute__((weak)) int32_t thp_deinit(void)
{
    return 0;
}

__attribute__((weak)) int32_t tui_get_tpdata_thp(ts_tui_finger* data)
{
    (void)data;
    return 0;
}
#endif
