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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "test_libc_func.h"

#define THREAD_NUM  5

struct testdata {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
};

static struct testdata td;

pthread_t  thread[THREAD_NUM];

int start_num = 0;
int waken_num = 0;


static void *thr_func(void *arg)
{
    int rc;
    pthread_t self = pthread_self();

    if (pthread_mutex_lock(&td.mutex) != 0) {
        fprintf(stderr, "[Thread 0x%p] failed to acquire the mutex\n", (void *)self);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    start_num ++;
    fprintf(stderr, "[Thread 0x%p] started and locked the mutex\n", (void *)self);

    fprintf(stderr, "[Thread 0x%p] is waiting for the cond\n", (void *)self);
    rc = pthread_cond_wait(&td.cond, &td.mutex);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_wait return %d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    waken_num ++;
    fprintf(stderr, "[Thread 0x%p] was wakened and acquired the mutex again\n",
        (void *)self);

    if (pthread_mutex_unlock(&td.mutex) != 0) {
        fprintf(stderr, "[Thread 0x%p] failed to release the mutex\n", (void *)self);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    fprintf(stderr, "[Thread 0x%p] released the mutex\n", (void *)self);
    return NULL;
}

int pthread_cond_signal_1_1()
{
    int i, j, rc;

    if (pthread_mutex_init(&td.mutex, NULL) != 0) {
        fprintf(stderr, "Fail to initialize mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_init(&td.cond, NULL) != 0) {
        fprintf(stderr, "Fail to initialize cond\n");
        return PTS_UNRESOLVED;
    }

    for (i = 0; i < THREAD_NUM; i++) {    /* create THREAD_NUM threads */
        if (pthread_create(&thread[i], NULL, thr_func, NULL) != 0) {
            fprintf(stderr, "Fail to create thread[%d]\n", i);
            return PTS_UNRESOLVED;
        }
    }
    while (start_num < THREAD_NUM) {    /* waiting for all threads started */
        tee_msleep(1);
        (void)sched_yield();
    }

    /* Acquire the mutex to make sure that all waiters are currently
       blocked on pthread_cond_wait */
    if (pthread_mutex_lock(&td.mutex) != 0) {
        fprintf(stderr, "Main: Fail to acquire mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_unlock(&td.mutex) != 0) {
        fprintf(stderr, "Main: Fail to release mutex\n");
        return PTS_UNRESOLVED;
    }

    /* signal once and check if at least one waiter is wakened */
    fprintf(stderr, "[Main thread] signals a condition\n");
    rc = pthread_cond_signal(&td.cond);
    if (rc != 0) {
        fprintf(stderr, "[Main thread] failed to signal the condition\n");
        return PTS_UNRESOLVED;
    }
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    if (waken_num <= 0) {
        fprintf(stderr, "[Main thread] but no waiters were wakened\n");
        printf("Test FAILED\n");

        return PTS_FAIL;
    }
    fprintf(stderr, "[Main thread] %d waiters were wakened\n", waken_num);

    for (j = 1; j < THREAD_NUM - 1; j++) {
        if (pthread_cond_signal(&td.cond) != 0) {
            fprintf(stderr, "Main failed to signal the condition\n");
            return PTS_UNRESOLVED;
        }

        (void)sched_yield();
    }
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    if (waken_num != THREAD_NUM - 1) {
        printf("sent %d but wake %d\n", THREAD_NUM - 1, waken_num);
        return PTS_FAIL;
    }

    /* loop to wake up the rest threads */
    if (pthread_cond_signal(&td.cond) != 0) {
        fprintf(stderr, "Main failed to signal the condition\n");
        return PTS_UNRESOLVED;
    }
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();

    if (waken_num != THREAD_NUM) {
        printf("sent %d but wake %d\n", THREAD_NUM, waken_num);
        return PTS_FAIL;
    }

    /* join all secondary threads */
    for (i = 0; i < THREAD_NUM; i++) {
        if (pthread_join(thread[i], NULL) != 0) {
            fprintf(stderr, "Fail to join thread[%d]\n", i);
            return PTS_UNRESOLVED;
        }
    }
    if (pthread_mutex_destroy(&td.mutex) != 0) {
        fprintf(stderr, "Fail to destroy mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_destroy(&td.cond) != 0) {
        fprintf(stderr, "Fail to destroy cond\n");
        return PTS_UNRESOLVED;
    }
    printf("Test PASSED\n");
    return PTS_PASS;
}
