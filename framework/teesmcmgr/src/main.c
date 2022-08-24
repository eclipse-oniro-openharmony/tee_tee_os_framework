/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: main functions of hmsmcmgr
 * Create: 2020-05-12
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
#include "teesmcmgr.h"

static cref_t g_teesmc_hdlr;
static rref_t g_sysctrl_hdlr;
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

void set_teesmc_hdlr(cref_t value)
{
    g_teesmc_hdlr = value;
}

cref_t get_teesmc_hdlr(void)
{
    return g_teesmc_hdlr;
}

void set_sysctrl_hdlr(rref_t value)
{
    g_sysctrl_hdlr = value;
}

rref_t get_sysctrl_hdlr(void)
{
    return g_sysctrl_hdlr;
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
    int32_t rc;

    set_teesmc_hdlr(irqmgr_acquire_teesmc_hdlr());
    if (is_ref_err(g_teesmc_hdlr))
        fatal("acquire teesmc hdlr returns %s\n", hmapi_strerror(ref_to_err(g_teesmc_hdlr)));

    set_sysctrl_hdlr(irqmgr_acquire_sysctrl_local_irq_hdlr());
    if (is_ref_err(g_sysctrl_hdlr))
        fatal("acquire sysctrl local irq hdlr returns %s\n", hmapi_strerror(ref_to_err(g_sysctrl_hdlr)));

    set_gtask_channel_hdlr(acquire_gtask_channel());
    if (is_ref_err(g_gtask_channel_hdlr))
        fatal("acquire gtask channel returns %s\n", hmapi_strerror(ref_to_err(g_gtask_channel_hdlr)));
    set_is_gtask_alive(true);

    rc = hm_tamgr_register("teesmcmgr");
    if (rc != 0) {
        error("tamgr registration failed\n");
        hm_exit(1);
    }
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
