/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: efuse libs header file
* Author: huawei
* Create: 2021/09/17
*/
#ifndef SYSCALL_API_COMMON_H
#define SYSCALL_API_COMMON_H

#define upper_32_bits(data) (uint32_t)(((data) >> 16) >> 16)
#define lower_32_bits(data) (uint32_t)(data)

/* array index */
#define ARRAY_INDEX0 0
#define ARRAY_INDEX1 1
#define ARRAY_INDEX2 2
#define ARRAY_INDEX3 3
#define ARRAY_INDEX4 4
#define ARRAY_INDEX5 5
#define ARRAY_INDEX6 6
#define ARRAY_INDEX7 7
#define ARRAY_INDEX8 8

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#endif
