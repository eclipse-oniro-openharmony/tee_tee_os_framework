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
#include <unistd.h>
#include <stdint.h>

#include "test_libc_func.h"

#define RETURN_CODE ((void*)100)    /* Set a random return code number. This shall be the return code of the
             thread when using pthread_exit().*/

# define INTHREAD 0     /* Control going to or is already for Thread */
# define INMAIN 1    /* Control going to or is already for Main */

static int sem;    /* Manual semaphore used to indicate when the thread has been created. */

/* Thread's function. */
static void *a_thread_func()
{
    sem = INMAIN;
    pthread_exit(RETURN_CODE);
    return NULL;
}

int pthread_join_2_1()
{
    pthread_t new_th;
    void *value_ptr;

    /* Initializing variables. */
    value_ptr = 0;
    sem = INTHREAD;

    /* Create a new thread. */
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error creating thread\n");
        return PTS_UNRESOLVED;
    }

    /* Make sure the thread was created before we join it. */
    while (sem == INTHREAD) {

        (void)sched_yield();
        tee_msleep(1);
    }
    /* Wait for thread to return */
    if (pthread_join(new_th, &value_ptr) != 0) {
        printf("Error in pthread_join()\n");
        return PTS_UNRESOLVED;
    }

    /* Check to make sure that 'value_ptr' that was passed to pthread_join() and the
     * pthread_exit() return code that was used in the thread funciton are the same. */
    if (value_ptr != RETURN_CODE) {
        printf("Test FAILED: pthread_join() did not return the pthread_exit value of the thread in 'value_ptr'.\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

