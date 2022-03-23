/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for real timer sleep
 * Create: 2019-08-20
 */

#ifndef SYS_LIBS_LIBTIMER_A32_SRC_NANOSLEEP_H
#define SYS_LIBS_LIBTIMER_A32_SRC_NANOSLEEP_H

#include <time.h>

int nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* SYS_LIBS_LIBTIMER_A32_SRC_NANOSLEEP_H */
