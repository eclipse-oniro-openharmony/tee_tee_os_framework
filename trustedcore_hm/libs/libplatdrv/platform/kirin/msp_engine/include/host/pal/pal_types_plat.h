/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: platform adapter for types
 * Create     : 2018/08/10
 */
#ifndef __PAL_TYPES_PLAT_H__
#define __PAL_TYPES_PLAT_H__
#include <stdint.h>
#include <stddef.h>

#ifndef INIT_TEXT
#define INIT_TEXT
#endif /* INIT_TEXT */

typedef signed char         s8;
typedef unsigned char       u8;
typedef short               s16;
typedef unsigned short      u16;
typedef int                 s32;
typedef unsigned int        u32;
typedef long long           s64;
typedef unsigned long long  u64;

typedef s32 err_bsp_t;

typedef u64 _pal_master_addr_t;

#endif /* __PAL_TYPES_PLAT_H__ */
