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
#include "test_libc_func.h"

int pthread_mutex_init_0_2()
{
    pthread_mutex_t  mutex;
    int rc;
    int rc1;

    /* Acquire the mutex object using pthread_mutex_lock */
    rc1 = pthread_mutex_lock(&mutex);

    fprintf(stderr, "Main: hold the mutex for a while\n");
    tee_msleep(1000);

    /* Release the mutex object using pthread_mutex_unlock */
    if ((rc = pthread_mutex_unlock(&mutex)) != 0) {
        fprintf(stderr, "Fail to unlock the mutex, rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Destory the mutex object */
    if ((rc = pthread_mutex_destroy(&mutex)) != 0) {
        fprintf(stderr, "Fail to destory the mutex, rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }
    if (rc1 == 0) {
        printf("lock an uninitialized lock should return non-zero\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
