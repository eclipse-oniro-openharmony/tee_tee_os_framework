/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
