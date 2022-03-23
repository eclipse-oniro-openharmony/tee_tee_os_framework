
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Common data types of the system
 * Author: Hisilicon multimedia software group
 * Create: 2020-6-10
 */

#ifndef __HI_TYPE_H__
#define __HI_TYPE_H__

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#if defined(__KERNEL__)
#include <linux/version.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif                          /* __cplusplus */

typedef unsigned char           HI_U8;
typedef unsigned char           HI_UCHAR;
typedef unsigned short          HI_U16;
typedef unsigned int            HI_U32;

typedef signed char             HI_S8;
typedef signed short            HI_S16;
typedef signed int              HI_S32;

#ifndef _M_IX86
typedef unsigned long long      HI_U64;
typedef long long               HI_S64;
#else
typedef __int64                 HI_U64;
typedef __int64                 HI_S64;
#endif

typedef char                    HI_CHAR;
typedef char*                   HI_PCHAR;
typedef const char*             HiConsPChar;

typedef float                   HI_FLOAT;
typedef double                  HI_DOUBLE;

#define HI_VOID                 void

#ifdef ENV_SOS_KERNEL
typedef unsigned long           HI_SIZE_T;
#else
typedef unsigned long long      HI_SIZE_T;
#endif

typedef unsigned long           HI_LENGTH_T;

typedef HI_U64                  HiTimeT;
typedef HI_U32                  HI_HANDLE;

typedef unsigned long           HI_VIRT_ADDR_T;

typedef unsigned long           HI_ULONG;

/* Constant Definition */
/* CNcomment: 常量定义  */
typedef enum {
    HI_FALSE = 0,
    HI_TRUE  = 1,
} HiBool;

/* optimize HwLiveWallPaper */
typedef enum OmxVdecSceneMode {
    VDEC_SCENE_DEFAULT,
    VDEC_SCENE_HW_LIVE_WALL_PAPER,
    VDEC_SCENE_HW_SNAPCHAT,
    VDEC_SCENE_HW_CLOUD_PC,
    VDEC_SCENE_HW_LOW_LATENCY,
    VDEC_SCENE_HW_MAXNUM,
} OmxVdecSceneMode;
/* optimize HwLiveWallPaper end */

#ifndef NULL
#define NULL              0L
#endif

#define HI_NULL           0L
#define HI_NULL_PTR       0L

#define HI_SUCCESS        0
#define HI_FAILURE        (-1)
#define HI_UNSUPPORT      (-2)

#define HI_INVALID_HANDLE 0xffffffff

#define HI_INVALID_PTS    0xffffffff
#define HI_INVALID_TIME   0xffffffff

#define HI_OS_LINUX       0xabcd
#define HI_OS_WIN32       0xcdef

#ifdef _WIN32
#define HI_OS_TYPE        HI_OS_WIN32
#else
#define __OS_LINUX__
#define HI_OS_TYPE        HI_OS_LINUX
#endif

#ifdef HI_ADVCA_SUPPORT
#define __INIT__
#define __EXIT__
#else
#define __INIT__  __init
#define __EXIT__  __exit
#endif

/*
 * define of HI_HANDLE :
 * bit31                                                           bit0
 *   |<----   16bit --------->|<---   8bit    --->|<---  8bit   --->|
 *   |--------------------------------------------------------------|
 *   |      HI_MOD_ID_E       |  mod defined data |     chnID       |
 *   |--------------------------------------------------------------|
 * mod defined data: private data define by each module(for example: sub-mod id), usually, set to 0.
 */

#define HI_HANDLE_MAKEHANDLE(mod, privatedata, chnid) \
    (HI_HANDLE)((((mod)& 0xffff) << 16) | ((((privatedata)& 0xff) << 8)) | (((chnid) & 0xff)))

#define HI_HANDLE_GET_MODID(handle)    (((handle) >> 16) & 0xffff)
#define HI_HANDLE_GET_PriDATA(handle)  (((handle) >> 8) & 0xff)
#define HI_HANDLE_GET_CHNID(handle)    (((handle)) & 0xff)

#define UNUSED(x) ((x) = (x))

typedef unsigned char           hi_uchar;
typedef unsigned char           hi_u8;
typedef unsigned short          hi_u16;
typedef unsigned int            hi_u32;
typedef unsigned long long      hi_u64;
typedef unsigned long           hi_ulong;

typedef char                    hi_char;
typedef signed char             hi_s8;
typedef short                   hi_s16;
typedef int                     hi_s32;
typedef long long               hi_s64;
typedef long                    hi_slong;

typedef float                   hi_float;
typedef double                  hi_double;

typedef void                    hi_void;

typedef unsigned long long      hi_size_t;
typedef unsigned long           hi_length_t;

typedef hi_u32                  hi_handle;

typedef HiBool                  hi_bool;

#if defined(__KERNEL__)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36))
#define DECLARE_MUTEX DEFINE_SEMAPHORE
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif                          /* __cplusplus */

#endif                          /* __HI_TYPE_H__ */
