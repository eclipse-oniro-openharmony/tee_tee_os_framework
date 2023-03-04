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

#define    THREAD_NUM      16
#define    LOOPS         1000
#define        VAR_NUM 10

static void *f1(void *parm);

static pthread_spinlock_t spinlock[VAR_NUM];
static int                value[VAR_NUM];    /* value protected by mutex */

int pthread_spin_lock_0_2()
{
    int                   i, j, rc;
    pthread_attr_t        pta;
    pthread_t             threads[THREAD_NUM];
    //pthread_t            self = pthread_self();

    for (i = 0; i < VAR_NUM; i++) {
        pthread_spin_init(&spinlock[i], NULL);
    }
    pthread_attr_init(&pta);
    pthread_attr_setdetachstate(&pta, PTHREAD_CREATE_JOINABLE);

    /* Create threads */
    fprintf(stderr, "Creating %d threads\n", THREAD_NUM);
    for (i = 0; i < THREAD_NUM; ++i) {
        rc = pthread_create(&threads[i], &pta, f1, (void *)(i + 1));
        if (rc)
            return PTS_FAIL;
    }
    /* Wait to join all threads */
    for (i = 0; i < THREAD_NUM; ++i)
        pthread_join(threads[i], NULL);
    pthread_attr_destroy(&pta);
    for (i = 0; i < VAR_NUM; i++) {
        pthread_spin_destroy(&spinlock[i]);
    }

    for (j = 0; j < VAR_NUM; j++) {
        /* Check if the final value is as expected */
        if (value[j] != (1 + THREAD_NUM) * THREAD_NUM / 2 * LOOPS) {
            fprintf(stderr, "Using %d threads and each loops %d times\n", THREAD_NUM,
                LOOPS);
            fprintf(stderr, "Final value must be %d instead of %d\n",
                (1 + THREAD_NUM) * THREAD_NUM / 2 * LOOPS, value[j]);
            printf("Test FAILED\n");
            return PTS_FAIL;
        }
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

void *f1(void *parm)
{
    int   i, tmp, j;
    int   rc = 0;
    int  step = (int)parm;

    /* Loopd M times to acquire the mutex, increase the value,
       and then release the mutex. */

    for (i = 0; i < LOOPS; ++i) {
        for (j = 0; j < VAR_NUM; j++) {
            rc = pthread_spin_lock(&spinlock[j]);
            if (rc != 0) {
                fprintf(stderr, "Error on pthread_mutex_lock(), rc=%d\n", rc);
                return (void *)(PTS_FAIL);
            }

            tmp = value[j];
            tmp = tmp + step;
            //fprintf(stderr,"Thread(0x%p) holds the mutex\n",(void*)self);
            //msleep(1);      /* delay the increasement operation */
            value[j] = tmp;

            rc = pthread_spin_unlock(&spinlock[j]);
            if (rc != 0) {
                fprintf(stderr, "Error on pthread_mutex_unlock(), rc=%d\n", rc);
                return (void *)(PTS_UNRESOLVED);
            }
            //sleep(1);
        }
    }
    pthread_exit(0);
    return (void *)(0);
}
