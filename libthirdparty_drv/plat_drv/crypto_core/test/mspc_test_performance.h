/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for mspc performance test.
 * Author : w00371137
 * Create: 2020/04/03
 */

#ifndef __MSPC_TEST_PERFORMANCE_H__
#define __MSPC_TEST_PERFORMANCE_H__

#include <stdint.h>

enum {
    MSPC_FUNC_CONNECT                   = 0x1,
    MSPC_FUNC_DISCONNECT                = 0x2,
    MSPC_FUNC_SCARD_SEND                = 0x3,
    MSPC_FUNC_SCARD_RECV                = 0x4,
};

#ifdef MSPC_TEST_PERFORMANCE
void mspc_record_start_time(void);
void mspc_record_end_time(uint32_t type);
#else
static inline void mspc_record_start_time(void)
{
}
static inline void mspc_record_end_time(uint32_t type)
{
    (void)type;
}
#endif

#endif /* __MSPC_TEST_PERFORMANCE_H__ */
