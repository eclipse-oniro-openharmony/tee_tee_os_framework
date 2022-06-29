/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: function defined in sre_syscall.c
 * Create: 2022-05-12
 */
#ifndef LIBTEEOS_SRE_SYSCALL_H
#define LIBTEEOS_SRE_SYSCALL_H

#include <stdint.h>
#include <timer_export.h> /* should not delete, used by other module */
#include "sre_typedef.h"

uint32_t __SRE_TaskSelf(uint32_t *puwTaskPID);
uint32_t __SRE_MemUsageGet(uint8_t ucPtNo);

#endif
