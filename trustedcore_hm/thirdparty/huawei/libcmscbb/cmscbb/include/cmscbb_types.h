/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_TYPES_H
#define H_CMSCBB_TYPES_H

#include <stdio.h>
#include <stdarg.h>

/* CVB: CMS Verify CBB */
typedef unsigned char   CVB_UINT8;
typedef char            CVB_INT8;
typedef unsigned short  CVB_UINT16;
typedef short           CVB_INT16;

#if defined(__LP64__) || defined(__64BIT__)
typedef unsigned int    CVB_UINT32;
typedef int             CVB_INT32;
typedef unsigned long long  CVB_ULONG;
typedef long long           CVB_LONG;
#else   /* int length is 16 for 16bit system */
typedef unsigned long   CVB_UINT32;
typedef long            CVB_INT32;
typedef unsigned long   CVB_ULONG;
typedef unsigned long   CVB_LONG;
#endif

typedef unsigned char   CVB_BYTE;
typedef char            CVB_CHAR;
typedef CVB_UINT32      CVB_BOOL;
typedef int             CVB_INT;
typedef unsigned int    CVB_UINT;
typedef size_t          CVB_SIZE_T;

typedef void*           CVB_FILE_HANDLE;
typedef va_list         cvb_va_list;

#define BIT_COUNT_OF_BYTE 8


#if defined(_MSC_VER)
typedef __int64 CVB_TIME_T;
#else
typedef long long CVB_TIME_T;
#endif

#define CMSCBB_MAX_INT  ((CVB_UINT32)-1)

#ifndef __CVB_NO_SEC_64BIT
#if defined(_MSC_VER)
typedef unsigned __int64  CVB_UINT64;
typedef __int64  CVB_INT64;
typedef CVB_ULONG       CVB_PTR;
#else
#   if defined(__linux__)
#       include<stdint.h>
typedef uintptr_t       CVB_PTR;
#   else
typedef CVB_ULONG       CVB_PTR;
#       if defined(__vxworks__)
#           if !defined(VXWORKS_VERSION) && !defined(__INCvxTypesh)
#               error "not able to identify vxworks platform"
#           endif  /* VXWORKS_VERSION */
#       endif  /* __vxworks__ */
#       if defined(VXWORKS_VERSION) || defined(__INCvxTypesh)
#           include<vxWorks.h>
#       else
#           include<inttypes.h>
#       endif  /* VXWORKS_VERSION */
#   endif  /* __linux__ */
#   if (defined(__GNUC__) && (__GNUC__< 3))
typedef unsigned long long  CVB_UINT64;
typedef long long  CVB_INT64;
#   else
typedef uint64_t CVB_UINT64;
typedef int64_t CVB_INT64;
#   endif
#endif  /* _MSC_VER */

#endif /* __CVB_NO_SEC_64BIT */

/* define error code */
typedef CVB_UINT32 CMSCBB_ERROR_CODE;


#ifndef CVB_SUCCESS
#define CVB_SUCCESS     0
#endif

#ifndef CVB_NULL
#define CVB_NULL        0
#endif
#ifndef CVB_TRUE
#define CVB_TRUE        (CVB_BOOL)(1)
#endif
#ifndef CVB_FALSE
#define CVB_FALSE       (CVB_BOOL)(0)
#endif
#ifndef CVB_VOID
#define CVB_VOID        void
#endif


#define cmscbb_va_start(lst, start_arg)  va_start(lst, start_arg);
#define cmscbb_va_end(lst)  va_end(lst)

/* maximum big integer length */
#define CMSCBB_MAX_INT_DIGITS 512UL

/* big integer define, big-endian */
typedef struct cmscbb_bigint_st {
    CVB_UINT32  uiLength;
    CVB_BYTE    aVal[CMSCBB_MAX_INT_DIGITS];
} CmscbbBigInt;

typedef struct cmscbb_datetime_st {
    CVB_UINT16 uYear;
    CVB_UINT8 uMonth;
    CVB_UINT8 uDay;
    CVB_UINT8 uHour;
    CVB_UINT8 uMinute;

    CVB_UINT16 uMillSecond;
    CVB_UINT8 uSecond;
    CVB_UINT8 uUtcFlag;    /* 0: not UTC, 1: UTC */
    CVB_UINT8 uUtcHour;
    CVB_UINT8 uUtcMinute;
} CmscbbDatetime;

#endif /* H_CMSCBB_TYPES_H */
