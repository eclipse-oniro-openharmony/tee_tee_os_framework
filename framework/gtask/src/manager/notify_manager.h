/* Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: used by notify_manager.
 * Author: yangboyu y30022050
 * Create: 2022-04-24
 */
#ifndef GTASK_NOTIFY_MANAGER_H
#define GTASK_NOTIFY_MANAGER_H

#include "sys_timer.h" // timer_private_data_kernel

#define NOTIFY_MEM_SIZE   (4 * 1024)

TEE_Result register_notify_memery(const smc_cmd_t *cmd);
struct notify_data_struct *get_notify_data(void);

#endif /* GTASK_NOTIFY_MANAGER_H */
