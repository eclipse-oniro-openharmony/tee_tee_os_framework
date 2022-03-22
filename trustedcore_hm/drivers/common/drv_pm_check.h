/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare drv suspend/resume msg check function
 * Create: 2021-07-12
 */
#ifndef DRIVERS_COMMON_DRV_PM_CHECK_H
#define DRIVERS_COMMON_DRV_PM_CHECK_H

#include <stdint.h>
#include <uapi/hm_msg_type.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hm_types.h>

int32_t pm_msg_param_check(uint16_t msg_id, cref_t msg_hdl,
    hm_msg_header *msg, const struct hmcap_message_info *info, pid_t auth_pid);

#endif
