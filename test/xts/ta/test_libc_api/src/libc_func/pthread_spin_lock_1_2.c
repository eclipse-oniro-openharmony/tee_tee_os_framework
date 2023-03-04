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

static pthread_spinlock_t spinlock;
volatile static int thread_state;

#define NOT_CREATED_THREAD 1
#define ENTERED_THREAD 2
#define EXITING_THREAD 3

static void *fn_chld(void *arg)
{
    int rc = 0;
    thread_state = ENTERED_THREAD;

    /* Lock the spinlock */
    printf("thread: attempt spin lock\n");
    rc = pthread_spin_lock(&spinlock);
    if (rc != 0) {
        printf("Test FAILED: child failed to get spin lock,error code:%d\n", rc);
        pthread_exit(PTS_FAIL);
    }
    printf("thread: acquired spin lock\n");

    /* Just some time between locking and unlocking */
    tee_msleep(1000);

    /* Unlock the spin lock */
    printf("thread: unlock spin lock\n");
    if (pthread_spin_unlock(&spinlock)) {
        printf("child: Error at pthread_spin_unlock()\n");
        pthread_exit(PTS_UNRESOLVED);
    }

    thread_state = EXITING_THREAD;
    pthread_exit(0);
    return NULL;
}


int pthread_spin_lock_1_2()
{
    int cnt = 0;

    pthread_t child_thread;

    /* Initialize spinlock */
    if (pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE) != 0) {
        printf("main: Error at pthread_spin_init()\n");
        return PTS_UNRESOLVED;
    }

    printf("main: attempt spin lock\n");

    /* We should get the lock */
    if (pthread_spin_lock(&spinlock) != 0) {
        printf("Test FAILED: main cannot get spin lock  when no one owns the lock\n");
        return PTS_FAIL;
    }
    printf("main: acquired spin lock\n");

    /* Initialize thread state */
    thread_state = NOT_CREATED_THREAD;

    /* Create thread */
    printf("main: create thread\n");
    if (pthread_create(&child_thread, NULL, fn_chld, NULL) != 0) {
        printf("main: Error creating child thread\n");
        return PTS_UNRESOLVED;
    }

    cnt = 0;
    /* Expect the child thread to spin on spin lock.  Wait for 3 seconds. */
    do {
        (void)sched_yield();
        tee_msleep(1000);
        (void)sched_yield();
    } while (thread_state != EXITING_THREAD && cnt++ < 3);

    if (thread_state == EXITING_THREAD) {
        printf("Test FAILED: child thread did not spin on spin lock when other thread holds the lock\n");
        return PTS_FAIL;
    } else if (thread_state != ENTERED_THREAD) {
        printf("main: Unexpected thread state %d\n", thread_state);
        return PTS_UNRESOLVED;
    }

    printf("main: unlock spin lock\n");
    if (pthread_spin_unlock(&spinlock) != 0) {
        printf("main: Error at pthread_spin_unlock()\n");
        return PTS_UNRESOLVED;
    }

    /* We expected the child get the spin lock and exit */
    cnt = 0;
    do {
        (void)sched_yield();
        tee_msleep(1000);
        (void)sched_yield();
    } while (thread_state != EXITING_THREAD && cnt++ < 3);

    if (thread_state == ENTERED_THREAD) {
        printf("Test FAILED: child thread did not get spin lock\n");
        return PTS_FAIL;
    } else if (thread_state != EXITING_THREAD) {
        printf("main: Unexpected thread state %d\n", thread_state);
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to finish execution */
    if (pthread_join(child_thread, NULL) != 0) {
        printf("main: Error at pthread_join()\n");
        return PTS_UNRESOLVED;
    }

    /* Destroy the spinlock */
    if (pthread_spin_destroy(&spinlock) != 0) {
        printf("Error at pthread_spin_destroy()");
        return PTS_UNRESOLVED;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
