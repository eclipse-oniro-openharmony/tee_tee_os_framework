/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: register drv dyn policy
 * Create: 2021-07-22
 */

#ifndef DRVMGR_SRC_DRV_DYN_POLICY_MGR_H
#define DRVMGR_SRC_DRV_DYN_POLICY_MGR_H

#include "task_mgr.h"

int32_t register_drv_policy(struct task_node *node);
void del_dynamic_policy_to_drv(const struct tee_uuid *uuid);
int32_t add_dynamic_policy_to_drv(const struct task_tlv *tlv);

#endif
