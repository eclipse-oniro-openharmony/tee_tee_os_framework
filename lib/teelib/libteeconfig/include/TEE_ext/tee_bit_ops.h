/* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: add for MACRO.
 * Create: 2019-10-09
 */
#ifndef __TEE_BIT_OPS_H_
#define __TEE_BIT_OPS_H_

#define LOW_32BIT(x) ((uintptr_t)(x) & 0xffffffff)

#ifdef __aarch64__
#define HIGH_32BIT(x) ((uint64_t)(uintptr_t)(x) >> 32)
#else
#define HIGH_32BIT(x) ((uint64_t)(uintptr_t)0)
#endif

#define GET_64BIT_ADDR(high, low) (((uint64_t)(high) << 32) | (low))
#endif
