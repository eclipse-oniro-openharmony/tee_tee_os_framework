/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2005-2018. All rights reserved.
 * Description: Common data types of the system. CNcomment: 系统共用的数据类型定义 CNend
 */

#ifndef __HI_TYPE_H__
#define __HI_TYPE_H__

typedef unsigned char           hi_uchar;
typedef unsigned char           hi_u8;
typedef unsigned short          hi_u16;
typedef unsigned int            hi_u32;
typedef unsigned long long      hi_u64;
typedef unsigned long           hi_ulong;

typedef char*                   hi_pchar;
typedef char                    hi_char;
typedef signed char             hi_s8;
typedef short                   hi_s16;
typedef int                     hi_s32;
typedef long long               hi_s64;
typedef long                    hi_slong;

typedef float                   hi_float;
typedef double                  hi_double;

typedef void                    hi_void;

typedef unsigned long           hi_size_t;
typedef unsigned long           hi_length_t;

typedef hi_u32                  hi_handle;

typedef unsigned int            hi_phys_addr_t;

#ifdef CONFIG_ARCH_LP64_MODE
typedef unsigned long long      hi_virt_addr_t;
#else
typedef unsigned int            hi_virt_addr_t;
#endif

typedef enum {
    HI_FALSE    = 0,
    HI_TRUE     = 1,
} hi_bool;

typedef unsigned long long      hi_mem_size_t;
typedef unsigned long long      hi_mem_handle_t;
typedef struct {
    hi_mem_handle_t mem_handle; /* Handle fo buffer header address */
    hi_mem_size_t addr_offset;  /* buffer offset */
} hi_mem_handle;

#define HI_NULL             0L
#define HI_NULL_PTR         0L

#define HI_SUCCESS          0
#define HI_FAILURE          (-1)

#define HI_INVALID_HANDLE   (0xffffffff)

#define HI_INVALID_PTS      (0xffffffff)
#define HI_INVALID_TIME     (0xffffffff)

/*
 * define of HI_HANDLE :
 * bit31                                                                bit0
 *   |<----- 8bit ----->|<----- 8bit ----->|<---------- 16bit ---------->|
 *   |-------------------------------------------------------------------|
 *   |    HI_MOD_ID_E   | mod defined data |            chnID            |
 *   |-------------------------------------------------------------------|
 * mod defined data: private data define by each module(for example: sub-mod id), usually, set to 0.
 */
#define HI_HANDLE_MAKEHANDLE(mod, private_data, chnid)  (hi_handle)((((mod) & 0xff) << 24) | ((((private_data) & 0xff) << 16)) | (((chnid) & 0xffff)))

#define HI_HANDLE_GET_MODID(handle)     (((handle) >> 24) & 0xff)
#define HI_HANDLE_GET_PriDATA(handle)   (((handle) >> 16) & 0xff)
#define HI_HANDLE_GET_CHNID(handle)     (((handle)) & 0xffff)

#define HI_UNUSED(x) ((x) = (x))

#endif /* __HI_TYPE_H__ */

