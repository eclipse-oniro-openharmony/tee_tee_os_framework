/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */


/* We are testing conformance to IEEE Std 1003.1, 2003 Edition */
#define _POSIX_C_SOURCE 200112L

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_libc_func.h"

#ifndef VERBOSE
#define VERBOSE 1
#endif

static int control = 0;

static void my_init(void)
{
    tee_msleep(1000);

    control = 1;

    return ;
}

/* The main test function. */
int pthread_once_2_1()
{
    int ret;

    pthread_once_t myctl = PTHREAD_ONCE_INIT;


    control = 0;

    /* Call the initializer */
    ret = pthread_once(&myctl, my_init);

    if (ret != 0) {
        printf("pthread_once failed\n");
        return PTS_FAIL;
    }

    if (control != 1) {
        printf("The initializer function did not execute\n");
        return PTS_FAIL;
    }

    return PTS_PASS;
}


