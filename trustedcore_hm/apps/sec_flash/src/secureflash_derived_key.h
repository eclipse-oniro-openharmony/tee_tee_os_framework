/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secureflash_derived_key.h
 * Author: l00265041
 * Create: 2019-8-17
 */
#ifndef __SECUREFLASH_DERIVED_KEY_H__
#define __SECUREFLASH_DERIVED_KEY_H__
#include <stdint.h>
#include "secureflash_api.h"

#define SECFLASH_CONSTANT_ENC  0x4
#define SECFLASH_CONSTANT_MAC  0x6
#define SECFLASH_CONSTANT_DEK  0x7

#define SECFLASH_SECURE_STORAGE_COUNT_START_BIT 0
#define SECFLASH_WEAVER_COUNT_START_BIT         10
#define SECFLASH_SECURE_STORAGE_COUNT_MASK      0x1F
#define SECFLASH_SECURE_STORAGE_BIT_ONE_MAX     31
#define SECFLASH_WEAVER_BIT_ONE_MAX             31

#endif

