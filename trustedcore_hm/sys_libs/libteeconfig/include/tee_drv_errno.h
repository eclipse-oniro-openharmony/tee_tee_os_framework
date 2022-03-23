/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare tee driver return value marco
 * Create: 2021-08-12
 */
#ifndef TEE_DRV_ERRNO_H
#define TEE_DRV_ERRNO_H
#include <stdint.h>

#define DRV_SUCCESS 0
#define DRV_GENERAL_ERR (-1)
#define DRV_CLOSE_FD_FAIL (-2)  /* find fd, but close fail */

#endif
