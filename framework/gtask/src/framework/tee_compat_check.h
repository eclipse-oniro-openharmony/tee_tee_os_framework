/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: for check compatibility between tzdriver and tee
 * Author: lipeng
 * Create: 2021-7-12
 */

#ifndef TEE_COMPAT_CHECK_H
#define TEE_COMPAT_CHECK_H

#include "tee_defines.h"

/*
 * this version number MAJOR.MINOR is used
 * to identify the compatibility of tzdriver and teeos
 */
#define TEEOS_COMPAT_LEVEL_MAJOR 0
#define TEEOS_COMPAT_LEVEL_MINOR 1

#define VER_CHECK_MAGIC_NUM 0x5A5A5A5A
#define COMPAT_LEVEL_BUF_LEN 12

void generate_teeos_compat_level(uint32_t *buffer, uint32_t size);
#endif
