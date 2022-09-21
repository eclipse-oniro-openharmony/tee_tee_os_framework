/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare funtion send msg to driver process
 * Create: 2021-07-19
 */
#ifndef DRVMGR_SRC_DRV_IPC_MGR_H
#define DRVMGR_SRC_DRV_IPC_MGR_H

#include <stdint.h>
#include <tee_defines.h>
#include "drv_dispatch.h"
#include "drv_dyn_conf_mgr.h"
#include "task_mgr.h"

#define DRV_IPC_MAX_TIMEOUT 2000 /* timeout is ms, 2000ms means 2s */

int64_t drv_open_handle(const struct tee_drv_param *params, const struct task_node *node, uint64_t perm);
int64_t call_drv_close(uint32_t taskid, const struct tee_uuid *caller_uuid, int64_t fd, cref_t channel);

#ifdef TEE_SUPPORT_DRV_FD_DUMP
void call_drv_dump(cref_t channel);
#endif

#endif
