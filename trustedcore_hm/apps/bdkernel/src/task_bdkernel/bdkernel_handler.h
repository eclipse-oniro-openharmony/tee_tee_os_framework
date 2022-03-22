/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for initializing user
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#ifndef HWAA_KHANDLER_H
#define HWAA_KHANDLER_H

#include "securec.h"
#include "tee_internal_api.h"

/* invoke the TEE interface to handle the kernel user init */
TEE_Result HandleKernelInitUser(uint32_t paramTypes, TEE_Param *params);

#endif
