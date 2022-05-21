/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: main functions of hmsmcmgr
 * Author: zhengxianyi zhengxianyi1@huawei.com
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
#ifdef CONFIG_DYNAMIC_CPU_NUM
#include <sys/teecall.h>
#endif
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

static void create_smc_thread(pthread_t *smc_thread, size_t smc_thread_len, uint32_t cpu_nr)
{
    uint32_t i;
    int32_t ret;
    bool flag = (smc_thread == NULL) || (smc_thread_len == 0);
    if (flag)
        fatal("the smc thread array is null\n");
    for (i = 0; i < cpu_nr; i++) {
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

        if (pthread_create(&smc_thread[i], &attr, tee_smc_thread, (void *)(uintptr_t)(unsigned long)(i)) != 0) {
            error("fail to create smc thread\n");
            hm_exit(1);
        }
    }
}
static void create_idle_thread(pthread_t *idle_thread, size_t idle_thread_len, uint32_t cpu_nr)
{
    uint32_t i;
    int32_t ret;
    uint32_t startup_core = (uint32_t)hm_get_current_cpu_id();
    struct idle_thread_params idle_arg[NR_CORES] = { { 0 } };
    bool flag = (idle_thread == NULL) || (idle_thread_len == 0);
    if (flag)
        fatal("the idle thread array is null\n");
    for (i = 0; i < cpu_nr; i++) {
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
        idle_arg[i].startup_core = startup_core;
        idle_arg[i].idle_core = i;

        if (pthread_create(&idle_thread[i], &attr, tee_idle_thread, (void *)(&idle_arg[i])) != 0) {
            error("fail to create idle thread\n");
            hm_exit(1);
        }
    }
}

static void get_actual_cpu_nr(int32_t *cpu_nr)
{
#ifdef CONFIG_DYNAMIC_CPU_NUM
    int32_t ret;

    ret = teecall_cap_get_cpu_nr(cpu_nr);
    if (ret) {
        error("get_cpu_nr failed: 0x%x\n", ret);
        hm_exit(1);
    }

    if (*cpu_nr < 0 || *cpu_nr > NR_CORES) {
        error("caution: cpu_nr %d is invald\n", *cpu_nr);
        hm_exit(1);
    }
    error("get_cpu_nr: %d\n", *cpu_nr);
#else
    *cpu_nr = NR_CORES;
#endif
}

/*
 * CODEREVIEW CHECKLIST
 * RET: cs_client_init: checked.
 *        irqmgr_acquire_teesmc_hdlr: checked.
 *        irqmgr_acquire_sysctrl_local_irq_hdlr: checked.
 *        acquire_gtask_channel: checked.
 *        hm_tamgr_register: checked.
 *        malloc: checked.
 *        pthread_create: checked.
 * CODEREVIEW CHECKLIST by Wang Nan <wangnan0@huawei.com>
 * CODEREVIEW CHECKLIST by Zhu Xing <zhuxing4@huawei.com>
 * CODEREVIEW CHECKLIST by Wen Yuzhong <wenyuzhong1@huawei.com>
 * CODEREVIEW CHECKLIST by liujian <liujian56@huawei.com>
 */
int main(void)
{
    uint32_t i;
    int32_t rc;
    int32_t cpu_nr = -1;
    pthread_t smc_thread[NR_CORES] = {0};
    pthread_t idle_thread[NR_CORES] = {0};

    hm_mmgr_clt_init(); /* must call this before mmap&malloc. */
    rc = cs_client_init(&g_sysmgr_client, __sysmgrch);
    if (rc != 0) {
        error("cs client init failed: %d\n", rc);
        hm_exit(1);
    }

    info(" --\n");
    info("| TEE SMC Manager\n");
    info(" --\n");

    get_actual_cpu_nr(&cpu_nr);
    acquire_hdlr();
    create_smc_thread(smc_thread, sizeof(smc_thread), (uint32_t)cpu_nr);
    create_idle_thread(idle_thread, sizeof(idle_thread), (uint32_t)cpu_nr);
    for (i = 0; i < (uint32_t)cpu_nr; i++) {
        rc = pthread_join(idle_thread[i], NULL);
        if (rc != 0) {
            error("idle thread join failed\n");
            hm_exit(1);
        }
    }
    for (i = 0; i < (uint32_t)cpu_nr; i++) {
        rc = pthread_join(smc_thread[i], NULL);
        if (rc != 0) {
            error("smc thread join failed\n");
            hm_exit(1);
        }
    }
    fatal("teesmcmgr exited unexpectedly\n");
    return 0;
}
