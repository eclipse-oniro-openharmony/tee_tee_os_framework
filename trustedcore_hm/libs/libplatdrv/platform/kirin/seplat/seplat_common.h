/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:Define common macro for seplat.
 * Create: 2021/02/08
 */

#ifndef SEPLAT_COMMON_H
#define SEPLAT_COMMON_H

#include <types.h>
#include <seplat_hal_log.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)                ((sizeof(a)) / (sizeof((a)[0])))
#endif

#ifndef UNUSED
#define UNUSED(a)                    ((void)(a))
#endif


#define IF_TRUE_RETURN(cond, ret) do { \
    if ((cond)) { \
        return (ret); \
    } \
} while (0)

#define IF_TRUE_RETURN_WITHLOG(cond, ret, fmt, args...) do { \
    if ((cond)) { \
        hal_print_error("%s : " fmt "", SEPLAT_ERROR_TAG, ## args); \
        return (ret); \
    } \
} while (0)

#define IF_TRUE_GOTO(cond, res, tag, msg) do { \
    if ((cond)) { \
        hal_print_error("%s : %s", SEPLAT_ERROR_TAG, (msg)); \
        ret = (res); \
        goto (tag); \
    } \
} while (0)

#define IF_TRUE_GOTO_WITHLOG(cond, res, tag, fmt, args...) do { \
    if ((cond)) { \
        hal_print_error("%s : " fmt "", SEPLAT_ERROR_TAG, ## args); \
        ret = (res); \
        goto (tag); \
    } \
} while (0)

#define IF_NULL_RETURN(p, errcode) do { \
    if (!(p)) {\
        hal_print_error("%d NULL\n", __LINE__); \
        return (errcode); \
    }\
} while (0)

#endif /* SEPLAT_COMMON_H */
