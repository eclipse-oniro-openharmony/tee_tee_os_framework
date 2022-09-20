/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Reference of TEE internal api and internal definitions
 * Author: Zhangdeyao  zhangdeyao@huawei.com
 * Create: 2020-01-06
 */

#ifndef GTASK_INIT_H
#define GTASK_INIT_H

#include <stdbool.h>
#include <sys/usrsyscall.h>

#define SHELL_ENVP_LEN 2
#define MAX_RESPAWNS 3
#define SHELL        "/picosh.elf"

#define RESERVED_SYSMGR_CRED (-1) /* defined in kernel/boot.c create_process() */

int init_main(void);
void init_shell(void);
bool is_sys_task(uint32_t task_id);
uint32_t get_timer_pid(void);
rref_t get_sysctrl_ref(void);
int32_t get_drvmgr_pid(uint32_t *task_id);

#endif
