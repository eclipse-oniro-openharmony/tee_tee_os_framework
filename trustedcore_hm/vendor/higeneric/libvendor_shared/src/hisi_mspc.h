/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for MSPC API drivers
 * Author : z00452790
 * Create: 2020/07/07
 */

#ifndef __HISI_MSPC_TASK_H__
#define __HISI_MSPC_TASK_H__

#include "stdint.h"

int32_t __hisi_mspc_fac_mode_enter(void);
int32_t __hisi_mspc_fac_mode_exit(void);
int32_t __hisi_mspc_power_on(uint32_t vote_id);
int32_t __hisi_mspc_power_off(uint32_t vote_id);
int32_t __hisi_mspc_recovery(uint32_t flags);
int32_t __hisi_mspc_check_secflash(uint32_t *status);
int32_t __hisi_mspc_secflash_writelock(uint32_t is_set_op);

#endif /* end of __HISI_MSPC_TASK_H__ */