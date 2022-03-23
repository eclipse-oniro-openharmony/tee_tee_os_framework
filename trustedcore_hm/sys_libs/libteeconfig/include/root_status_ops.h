/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, root status function
 * Create: 2019-11-20
 */
#ifndef ROOT_STATUS_OPS_H
#define ROOT_STATUS_OPS_H
#include "sre_typedef.h"

UINT32 __SRE_ReadRootStatus();
int __SRE_WriteRootStatus(UINT32 status);
#endif /* ROOT_STATUS_OPS_H */
