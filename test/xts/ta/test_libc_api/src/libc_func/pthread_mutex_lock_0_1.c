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

#define _XOPEN_SOURCE 600

#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include "test_libc_func.h"

#define    THREAD_NUM      5
#define    LOOPS         4

static void *f1(void *parm);

static pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
static int                value = 0;    /* value protected by mutex */

int pthread_mutex_lock_0_1()
{
    int                   i, rc;
    pthread_attr_t        pta;
    pthread_t             threads;

    pthread_attr_init(&pta);

    if (0 != pthread_mutex_lock(&mutex)) {
        printf("failed mutex lock\n");
        return PTS_FAIL;
    }
    /* Create threads */
    for (i = 0; i < THREAD_NUM; ++i)
        rc = pthread_create(&threads, &pta, f1, NULL);

    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();

    if (value == 1) {
        printf("lock didn't take effect\n");
        return PTS_FAIL;
    }

    if (0 != pthread_mutex_unlock(&mutex)) {
        printf("faile to unlock\n");
        return PTS_FAIL;
    }

    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();

    if (value == 0) {
        printf("lock didn't take effect2\n");
        return PTS_FAIL;
    }

    pthread_join(threads, NULL);
    pthread_attr_destroy(&pta);
    pthread_mutex_destroy(&mutex);


    printf("Test PASSED\n");
    return PTS_PASS;
}

void *f1(void *parm)
{
    int   rc = 0;

    /* Loopd M times to acquire the mutex, increase the value,
       and then release the mutex. */

    rc = pthread_mutex_lock(&mutex);
    if (rc != 0) {
        fprintf(stderr, "Error on pthread_mutex_lock(), rc=%d\n", rc);
        return (void *)(PTS_FAIL);
    }
    value = 1;
    rc = pthread_mutex_unlock(&mutex);
    if (rc != 0) {
        fprintf(stderr, "Error on pthread_mutex_unlock(), rc=%d\n", rc);
        return (void *)(PTS_UNRESOLVED);
    }

    pthread_exit(0);
    return (void *)(0);
}
