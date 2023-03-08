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

#include <pthread.h>
#include <stdio.h>

#include "test_libc_func.h"

/* Keeps track of how many times the init function has been called. */
int init_flag;

/* The init function that pthread_once calls */
static void *an_init_func()
{
    init_flag++;
    return NULL;
}

int pthread_once_1_1()
{
    pthread_once_t once_control = PTHREAD_ONCE_INIT;

    init_flag = 0;

    /* Call pthread_once, passing it the once_control */
    pthread_once(&once_control, (void *)an_init_func);

    /* Call pthread_once again. The init function should not be
     * called. */
    pthread_once(&once_control, (void *)an_init_func);

    if (init_flag != 1) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;

}


