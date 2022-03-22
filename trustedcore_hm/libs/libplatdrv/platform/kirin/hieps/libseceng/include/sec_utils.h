/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: pal_lib function
 * Author: z00293770
 * Create: 2019-03-25
 */

#ifndef __SEC_UTILS_H__
#define __SEC_UTILS_H__
#include <pal_log.h>

#define SIZE_ALIGN_IN_WORD(bytes)  BIT_ALIGN(bytes, 2)

err_bsp_t sec_convert_big_to_little_endian(u8 *dst, u32 dst_max, u8 *src, u32 src_len);

err_bsp_t sec_convert_little_to_big_endian(u8 *dst, u32 dst_max, u8 *src, u32 src_len);

#endif /* __SEC_UTILS_H__ */
