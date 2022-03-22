/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: define types
 *              platform-dependent types is defined in pal_types_plat.h
 *              platform-independent types is defined in pal_types.h
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/10
 */

#ifndef __PAL_ERRNO_PLAT_H__
#define __PAL_ERRNO_PLAT_H__
#ifdef ERROR
#undef ERROR
#endif

#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif
#include <pal_types.h>
#include "hieps_seceng_errno.h"

#endif /* __PAL_ERRNO_PLAT_H__ */

