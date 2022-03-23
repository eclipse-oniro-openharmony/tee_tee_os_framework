/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare drv suspend/resume function
 * Create: 2021-03-01
 */
#ifndef TEE_DRV_SERVER_SRC_DRV_PM_H
#define TEE_DRV_SERVER_SRC_DRV_PM_H

#include <cs.h>

intptr_t driver_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);

#endif
