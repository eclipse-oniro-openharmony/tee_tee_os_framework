/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: declare SRE_TaskDelete function, keep compatibility for thirdpart driver
 * Create: 2019-11-20
 */
#ifndef PLATDRV_LEGACY_DEF_H
#define PLATDRV_LEGACY_DEF_H
#include <sre_typedef.h>

uint32_t SRE_TaskDelete(UINT32 uwTaskPID);

#define OS_CACHE_LINE_SIZE 64

#endif /* PLATDRV_LEGACY_DEF_H */
