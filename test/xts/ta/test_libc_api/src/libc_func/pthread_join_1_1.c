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

int end_exec;    /* Global flag indicating the the thread function has finished execution. */

/* Thread's function. */
static void *a_thread_func()
{
    int i;

    printf("Wait for 3 seconds for thread to finish execution:\n");
    for (i = 1; i < 4; i++) {
        printf("Waited (%d) second\n", i);
        tee_msleep(1);
    }

    /* Indicate that the thread has ended execution. */
    end_exec = 1;

    pthread_exit(0);
    return NULL;
}

int pthread_join_1_1()
{
    pthread_t new_th;

    /* Initialize flag */
    end_exec = 0;

    /* Create a new thread. */
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error creating thread\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to return */
    if (pthread_join(new_th, NULL) != 0) {
        printf("Error in pthread_join()\n");
        return PTS_UNRESOLVED;
    }

    if (end_exec == 0) {
        printf("Test FAILED: When using pthread_join(), main() did not wait for thread to finish execution before continuing.\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;

}
