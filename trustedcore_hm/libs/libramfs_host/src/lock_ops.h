/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: ramfs header
 * Create: 2018-05-18
 */

#ifndef _LOCK_OPS_H
#define _LOCK_OPS_H

#include <stdbool.h>
#include <stdint.h>

bool trylockr(volatile int32_t *l);
bool trylockw(volatile int32_t *l);
void unlock(volatile int32_t *l);

#endif
