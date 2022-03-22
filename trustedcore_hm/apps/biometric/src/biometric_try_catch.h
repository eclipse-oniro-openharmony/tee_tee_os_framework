/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: biometric try catch macro
 * Author: z00387284
 * Create: 2019-11-02
 */
#ifndef __BIOMATRIC_TRY_CATCH_H
#define __BIOMATRIC_TRY_CATCH_H
#include <stdint.h>
#include "tee_log.h"

#define bio_print tloge

#define __TRY                          \
    uint32_t __errorcode = 0;          \
    uint32_t __errorline = 0xFFFFFFFF; \
    uint32_t __logpara1 = 0;

#define __CATCH \
    __tabErr:   \
    bio_print("[%s] line(%d),error(%u),para(%u)\n", __FUNCTION__, __errorline, __errorcode, __logpara1);

#define SET_PARA(para)                 \
    {                                  \
        __logpara1 = (uint32_t)(para); \
    }
#define ERR_PROC()              \
    {                           \
        __errorline = __LINE__; \
        goto __tabErr;          \
    }
#define THROW(errcode)           \
    {                            \
        __errorcode = (errcode); \
        ERR_PROC()               \
    }
#define THROW_IF(expr, errcode) \
    {                           \
        if (expr) {             \
            THROW(errcode)      \
        }                       \
    }
#define THROW_IF_NULL(ptr, errcode) \
    {                               \
        if (!(ptr)) {               \
            THROW(errcode)          \
        }                           \
    }
#define THROW_IF_WITH_PARA(expr, errcode, para) \
    {                                           \
        if (expr) {                             \
            SET_PARA(para);                     \
            THROW(errcode)                      \
        }                                       \
    }

#define RETURN_VOID_IF(expr) \
    {                        \
        if (expr) {          \
            return;          \
        }                    \
    }
#define RETURN_IF(expr, errcode) \
    {                            \
        if (expr) {              \
            return (errcode);    \
        }                        \
    }
#define RETURN_IF_NULL(ptr, errcode) \
    {                                \
        if (!(ptr)) {                \
            return (errcode);        \
        }                            \
    }

#define ERR_CODE (__errorcode)

#endif
