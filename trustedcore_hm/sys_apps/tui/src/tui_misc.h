/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: the misc function for tui task
 * Create: 2020-04-06
 */
#ifndef TASK_TUI_MISC_H
#define TASK_TUI_MISC_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

bool tui_get_usermode(void);
void tee_task_entry_internal(int32_t init_build);
#endif /* TASK_TUI_MISC_H */