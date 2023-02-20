/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <procmgr.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/hmapi.h>
#include <securec.h>
#include <string.h>
#include <malloc.h>
#include <tamgr_ext.h>
#include <mmgrapi.h>
#include <irqmgr_api.h>
#include <sys/usrsyscall.h>
#include <sys/kuapi.h>
#include <sys/usrsyscall_smc.h>
#include "teesmcmgr.h"

static rref_t g_gtask_channel_hdlr;
static bool   g_is_gtask_alive;

void set_is_gtask_alive(bool value)
{
    g_is_gtask_alive = value;
}

bool get_is_gtask_alive(void)
{
    return g_is_gtask_alive;
}

void set_gtask_channel_hdlr(rref_t value)
{
    g_gtask_channel_hdlr = value;
}

rref_t get_gtask_channel_hdlr(void)
{
    return g_gtask_channel_hdlr;
}

static void acquire_hdlr(void)
{
    init_teesmc_hdlr();
    init_sysctrl_hdlr();
    set_gtask_channel_hdlr(acquire_gtask_channel());
    if (is_ref_err(g_gtask_channel_hdlr))
        fatal("acquire gtask channel returns %s\n", hmapi_strerror(ref_to_err(g_gtask_channel_hdlr)));
    set_is_gtask_alive(true);
}

static void create_smc_thread(pthread_t *smc_thread)
{
    int32_t ret;

    pthread_attr_t attr;
    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        error("fail to init smc thread\n");
        hm_exit(1);
    }
    void *stackaddr = malloc(SMCMGR_STACK_SIZE);
    if (stackaddr == NULL) {
        error("malloc stack space failed\n");
        hm_exit(1);
    }
    ret = pthread_attr_setstack(&attr, stackaddr, SMCMGR_STACK_SIZE);
    if (ret != 0) {
        error("smc thread set stack failed\n");
        hm_exit(1);
    }

    if (pthread_create(smc_thread, &attr, tee_smc_thread, NULL) != 0) {
        error("fail to create smc thread\n");
        hm_exit(1);
    }
}
static void create_idle_thread(pthread_t *idle_thread)
{
    int32_t ret;

    pthread_attr_t attr;
    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        error("fail to init idle thread\n");
        hm_exit(1);
    }
    void *stackaddr = malloc(SMCMGR_STACK_SIZE);
    if (stackaddr == NULL) {
        error("malloc stack space failed\n");
        hm_exit(1);
    }
    ret = pthread_attr_setstack(&attr, stackaddr, SMCMGR_STACK_SIZE);
    if (ret != 0) {
        error("idle thread set stack failed\n");
        hm_exit(1);
    }

    if (pthread_create(idle_thread, &attr, tee_idle_thread, NULL) != 0) {
        error("fail to create idle thread\n");
        hm_exit(1);
    }
}

int main(void)
{
    int32_t rc;
    pthread_t smc_thread = 0;
    pthread_t idle_thread = 0;

    info(" --\n");
    info("| TEE SMC Manager\n");
    info(" --\n");

    acquire_hdlr();
    create_smc_thread(&smc_thread);
    create_idle_thread(&idle_thread);

    rc = pthread_join(idle_thread, NULL);
    if (rc != 0) {
        error("idle thread join failed\n");
        hm_exit(1);
    }

    rc = pthread_join(smc_thread, NULL);
    if (rc != 0) {
        error("smc thread join failed\n");
        hm_exit(1);
    }
    fatal("teesmcmgr exited unexpectedly\n");

    return 0;
}
