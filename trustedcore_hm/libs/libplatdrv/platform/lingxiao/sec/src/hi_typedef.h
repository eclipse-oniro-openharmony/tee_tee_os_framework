/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Description: header files
 * Author: hsan
 * Create: 2019-1-31
 * History: 2019-1-31 hsan code restyle
 */

#ifndef __HI_TYPEDEF_H__
#define __HI_TYPEDEF_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*********************************************************/

#define HI_DISABLE 0
#define HI_ENABLE  1

#define HI_FALSE 0
#define HI_TRUE  1

#ifndef hi_void
#define hi_void void
#endif

/*********************************************************/

#ifndef hi_char8
#define hi_char8 char
#endif

#ifndef hi_short16
#define hi_short16 short
#endif

#ifndef hi_int32
#define hi_int32 int
#endif

#ifndef hi_long32
#define hi_long32 long
#endif

#ifndef hi_long64
#define hi_long64 long long
#endif

/*********************************************************/

#ifndef hi_uchar8
#define hi_uchar8 unsigned char
#endif

#ifndef hi_ushort16
#define hi_ushort16 unsigned short
#endif

#ifndef hi_uint32
#define hi_uint32 unsigned int
#endif

#ifndef hi_ulong32
#define hi_ulong32 unsigned long
#endif

#ifndef hi_ulong64
#define hi_ulong64 unsigned long long
#endif

#ifndef hi_uint64
#define hi_uint64 unsigned long long
#endif

/*********************************************************/

#ifndef hi_size_t
#define hi_size_t hi_uint32
#endif

/*********************************************************/

#ifndef hi_v_u8
#define hi_v_u8 volatile unsigned char
#endif

#ifndef hi_iomem
#define hi_iomem hi_void __iomem
#endif

#ifndef hi_v_u16
#define hi_v_u16 volatile unsigned short
#endif

#ifndef hi_v_u32
#define hi_v_u32 volatile unsigned int
#endif

#ifndef hi_v_u64
#define hi_v_u64 volatile unsigned long long
#endif

#ifndef hi_handle
#define hi_handle unsigned long
#endif

#define HI_NULL  0

/*********************************************************/

#ifndef hi_io_address
#define hi_io_address(x) (x)
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TYPEDEF_H__ */
