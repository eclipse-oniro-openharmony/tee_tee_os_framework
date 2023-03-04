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
#include <errno.h>
#include "test_libc_func.h"

typedef struct my_data {
    pthread_mutex_t     mutex;   /* Protects access to value */
    int                 value;   /* Access protected by mutex */
} my_data_t;

static my_data_t data = {PTHREAD_MUTEX_INITIALIZER, 0};

int pthread_mutex_init_3_1()
{
    printf("Test PASSED\n");
    return PTS_PASS;
}
