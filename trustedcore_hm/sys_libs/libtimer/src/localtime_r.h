/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for real timer localtime
 * Create: 2019-08-20
 */

#ifndef SYS_LIBS_LIBTIMER_A32_SRC_LOCALTIME_R_H
#define SYS_LIBS_LIBTIMER_A32_SRC_LOCALTIME_R_H

#include <time.h>
#include <timer.h>

#define weak_alias(old, new) __typeof(old)(new) __attribute__((weak, alias(#old)))

#define MAX_SECONDS_PER_YEAR 31622400LL
#define INT_MIN              ((-1) - 0x7fffffff)
#define INT_MAX              0x7fffffff

struct tm *__localtime_r(const time_t *restrict t, struct tm *restrict tm);
weak_alias(__localtime_r, localtime_r);

#endif /* SYS_LIBS_LIBTIMER_A32_SRC_LOCALTIME_R_H */
