/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define auth function
 * Create: 2021-03-17
 */
#ifndef TEE_DRV_SERVER_SRC_DRV_AUTH_H
#define TEE_DRV_SERVER_SRC_DRV_AUTH_H
#include <stdint.h>
#include <stdbool.h>
#include <tee_defines.h>
#include "drvcall_dyn_conf_mgr.h"
#include "drv_dyn_conf_mgr.h"
#include "task_mgr.h"

bool drv_mac_open_auth_check(const struct drv_conf_t *drv_conf, const struct tee_uuid *uuid);
bool caller_open_auth_check(const struct task_node *call_node, const char *drv_name, uint32_t name_len);
int32_t get_drvcaller_cmd_perm(const struct task_node *call_node, const struct task_node *dnode, uint64_t *perm);

#endif
