/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, root status function
 * Create: 2019-11-20
 */
#ifndef ROOT_STATUS_OPS_H
#define ROOT_STATUS_OPS_H
#include <stdint.h>

uint32_t tee_read_root_status();
int __SRE_WriteRootStatus(uint32_t status);
#endif /* ROOT_STATUS_OPS_H */
