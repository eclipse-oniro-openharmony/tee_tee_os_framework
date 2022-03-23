/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: timer implementation for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-04-22
 */
#ifndef TASK_TUI_TIMER_H
#define TASK_TUI_TIMER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys_timer.h>

#include "tui_drv_types.h"

int32_t timer_node_create(timeval_t interval, enum tui_drv_msg msg_id, int32_t caller_pid);
void timer_node_destroy(enum tui_drv_msg msg_id);
void timer_node_start(enum tui_drv_msg msg_id);
void timer_node_stop(enum tui_drv_msg msg_id);
void tui_timer_init(void);
void tui_timer_release(void);
void set_timer_enabled(bool enabled);
#endif /* TASK_TUI_TIMER_H */
