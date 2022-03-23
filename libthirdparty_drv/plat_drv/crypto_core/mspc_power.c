/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Drivers for MSP core power operation.
 * Author : w00371137
 * Create: 2019/11/08
 */

#include <mspc_power.h>
#include <mspc_errno.h>
#include <mspc.h>
#include <mspc_mem_layout.h>
#include <tee_log.h>
#include <hmlog.h>
#include <timer_export.h>
#include <ipc_call.h> /* __ipc_smc_switch */
#include <drv_mem.h> /* sre_mmap */
#include <sre_sys.h> /* SRE_DelayMs */
#include <soc_sctrl_interface.h>
#include <soc_acpu_baseaddr_interface.h>
#include <securec.h>
#include <register_ops.h>

#define MSPC_THIS_MODULE            MSPC_MODULE_POWER

/* msp core power flag */
#define MSPC_POWER_FLAG_ADDR    \
    SOC_SCTRL_SCBAKDATA10_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)
#define MSPC_POWER_ON_BIT             11
#define MSPC_LOWPOWER_BIT             12

/* access mspc area status */
#define MSPC_ACCESS_FLAG_ADDR   \
    SOC_SCTRL_SCBAKDATA6_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)
#define MSPC_ACCESS_BIT               31

/* MSPC_VOTE_STATUS_OFF must sync with atf mspc_power.c */
#define MSPC_VOTE_STATUS_OFF          0x555555555555

#define MSPC_VOTE_MASK                0xF
#define MSPC_VOTE_UNIT_ON             0xA
#define MSPC_VOTE_UNIT_OFF            0x5
#define MSPC_VOTE_UNIT_SIZE           4 /* 4 bits */

#define MSPC_UPGRADING_FLAG_MAGIC     0x7F348B5A

#define UNUSED(x) ((void)(x))

enum {
    MSPC_POWER_MUTEX_ERR              = MSPC_ERRCODE(0x10),
    MSPC_POWER_UPGRADE_ERR            = MSPC_ERRCODE(0x11),
};

enum mspc_fac_mode_flag {
    MSPC_IS_FACTORY_MODE,
    MSPC_IS_NOT_FACTORY_MODE,
};

/* 本接口为调用中软提供的库,中软未提供头文件.已备案 */
extern int __ipc_smc_switch(unsigned int irq);
static pthread_mutex_t g_power_mutex;
static uint32_t g_share_mem_vir;
static union mspc_vote_status g_vote_status = {
    .value = MSPC_VOTE_STATUS_OFF,
};
static uint32_t g_mspc_fac_mode = MSPC_IS_NOT_FACTORY_MODE;
timer_event *g_mspc_timer = NULL;

uint32_t mspc_get_power_status(void)
{
    if ((read32(MSPC_POWER_FLAG_ADDR) & BIT(MSPC_POWER_ON_BIT)) == 0)
        return MSPC_STATE_POWER_DOWN;

    return MSPC_STATE_POWER_UP;
}

uint32_t mspc_get_shared_ddr(void)
{
    int32_t ret;
    paddr_t share_phy_mem = (paddr_t)MSPC_DDR_LAST_PAGE_ADDR;
    uint32_t size = MSPC_DDR_LAST_PAGE_SIZE;

    if (g_share_mem_vir == 0) {
        ret = sre_mmap(share_phy_mem, size,
                       &g_share_mem_vir, secure, non_cache);
        if (ret != SRE_OK)
            tloge("%s: Map share memory failed! ret=%d\n", __func__, ret);
    }
    return g_share_mem_vir;
}

static uint32_t mspc_check_factory_mode(void)
{
    return g_mspc_fac_mode;
}

static void mspc_record_vote_status(void)
{
    int32_t ret;
    paddr_t share_phy_mem = (paddr_t)MSPC_DDR_LAST_PAGE_ADDR;
    const uint32_t size = MSPC_DDR_LAST_PAGE_SIZE;
    uint32_t addr;

    if (g_share_mem_vir == 0) {
        ret = sre_mmap(share_phy_mem, size,
                       &g_share_mem_vir, secure, non_cache);
        if (ret != SRE_OK) {
            tloge("MSPC: Map share memory failed! ret=%d\n", ret);
            return;
        }
    }

    addr = g_share_mem_vir + MSPC_TEE_VOTE_STATUS_OFFSET;
    *((uint64_t *)(uintptr_t)addr) = g_vote_status.value;
}

static uint64_t mspc_get_vote_status(void)
{
    return g_vote_status.value;
}

static void mspc_clear_vote_status(void)
{
    g_vote_status.value = MSPC_VOTE_STATUS_OFF;
    mspc_record_vote_status();
}

static void mspc_set_vote_status(uint32_t vote_id, int32_t cmd)
{
    uint64_t vote_unit;
    uint32_t vote_shif;

    vote_shif = (uint32_t)(MSPC_VOTE_UNIT_SIZE * vote_id);
    g_vote_status.value &= ~((uint64_t)MSPC_VOTE_MASK << vote_shif);

    if (cmd == MSPC_VOTE_ON)
        vote_unit = (uint64_t)MSPC_VOTE_UNIT_ON;
    else
        vote_unit = (uint64_t)MSPC_VOTE_UNIT_OFF;

    g_vote_status.value |= vote_unit << vote_shif;
    mspc_record_vote_status();
}

#define MSPC_RETRY_POWER_COUNT        2000
static int32_t mspc_power_on_ctrl(void)
{
    int32_t ret;

    /* If timer exist, destroy it. */
    if (g_mspc_timer) {
        ret = __SRE_TimerEventStop(g_mspc_timer);
        if (ret != SRE_OK)
            tloge("%s: stop timer :%d\n", __func__, ret);
        ret = __SRE_TimerEventDestroy(g_mspc_timer);
        if (ret != SRE_OK)
            tloge("%s: destroy timer failed:%d\n", __func__, ret);
        else
            g_mspc_timer = NULL;
    }

    return __ipc_smc_switch(TEE_MSPC_POWER_ON);
}

int32_t mspc_power_on(uint32_t vote_id)
{
    int32_t ret = MSPC_OK;
    uint64_t vote_status;

    if (vote_id >= MSPC_MAX_VOTE_ID) {
        tloge("%s:Invalid vote id:%d\n", __func__, vote_id);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    (void)pthread_mutex_lock(&g_power_mutex);
    if (mspc_check_factory_mode() == MSPC_IS_FACTORY_MODE && vote_id != MSPC_FACTORY_VOTE_ID) {
        tloge("%s:need wait factory mode exit:%d\n", __func__, vote_id);
        ret = MSPC_ERRCODE(CHECK_FAC_MODE_ERR);
        goto exit;
    }

    vote_status = mspc_get_vote_status();
    if (vote_status == MSPC_VOTE_STATUS_OFF) {
        /* power on mspc */
        ret = mspc_power_on_ctrl();
        if (ret != MSPC_OK) {
            tloge("%s:vote %d power on mspc failed: %d\n",
                  __func__, vote_id, ret);
            goto exit;
        }
    }

    mspc_set_vote_status(vote_id, MSPC_VOTE_ON);
exit:
    (void)pthread_mutex_unlock(&g_power_mutex);
    return ret;
}

static int32_t mspc_timer_handler(void)
{
    volatile uint64_t vote_status;
    int32_t ret;

    (void)pthread_mutex_lock(&g_power_mutex);
    vote_status = mspc_get_vote_status();
    if (vote_status != MSPC_VOTE_STATUS_OFF) {
        tloge("%s: mspc has been poweron. vote_status = 0x%llx\n",
              __func__, vote_status);
        ret = MSPC_ERROR;
        goto exit;
    }
    ret = __ipc_smc_switch(TEE_MSPC_POWER_OFF);
exit:
    (void)pthread_mutex_unlock(&g_power_mutex);

    return ret;
}

static int32_t mspc_power_off_ctrl(void)
{
    int32_t ret;
    timeval_t time;
    uint32_t data = 0;

    time.tval64 = 0;
    time.tval.sec = 10; /* 10s */

    if (!g_mspc_timer) {
        g_mspc_timer = __SRE_TimerEventCreate((sw_timer_event_handler)mspc_timer_handler,
                                              TIMER_CLASSIC, &data);
        if (!g_mspc_timer) {
            tloge("%s: Create timer failed!\n", __func__);
            return __ipc_smc_switch(TEE_MSPC_POWER_OFF);
        }
    }

    ret = __SRE_TimerEventStart(g_mspc_timer, &time);
    if (ret != SRE_OK) {
        tloge("%s: start timer failed: %d\n", __func__, ret);
        return __ipc_smc_switch(TEE_MSPC_POWER_OFF);
    }
    return MSPC_OK;
}

int32_t mspc_power_off(uint32_t vote_id)
{
    int32_t ret = MSPC_OK;
    volatile uint64_t vote_status;

    if (vote_id >= MSPC_MAX_VOTE_ID) {
        tloge("%s:Invalid vote id:%d\n", __func__, vote_id);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    (void)pthread_mutex_lock(&g_power_mutex);

    vote_status = mspc_get_vote_status();
    if (vote_status == MSPC_VOTE_STATUS_OFF) {
        tloge("%s: mspc is already off\n", __func__);
        (void)pthread_mutex_unlock(&g_power_mutex);
        return MSPC_OK;
    }

    /*
     * Vote firstly, then check whether the vote_status is off,
     * if the status is off, then power_off the mspc.
     */
    mspc_set_vote_status(vote_id, MSPC_VOTE_OFF);

    vote_status = mspc_get_vote_status();
    if (vote_status == MSPC_VOTE_STATUS_OFF) {
        /* Power off mspc */
        ret = mspc_power_off_ctrl();
        if (ret != MSPC_OK) {
            tloge("%s: vote %d power off mspc failed: %d\n",
                  __func__, vote_id, ret);
            /* Recover the vote status if power off failed. */
            mspc_set_vote_status(vote_id, MSPC_VOTE_ON);
        }
    }

    (void)pthread_mutex_unlock(&g_power_mutex);
    return ret;
}

static int32_t mspc_check_ready(void)
{
    return __ipc_smc_switch(TEE_MSPC_CHECK_READY);
}

int32_t mspc_wait_state(uint32_t state, uint32_t timeout)
{
    struct timespec start_ts = {0};
    struct timespec end_ts = {0};
    uint32_t ready;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ready = mspc_check_ready();
    while (ready != state) {
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        if (end_ts.tv_sec < start_ts.tv_sec ||
            (uint32_t)(end_ts.tv_sec - start_ts.tv_sec) > timeout) {
            tloge("%s:timeout!end:%d, start:%d,time:%ds\n",
                  __func__, end_ts.tv_sec, start_ts.tv_sec, timeout);
            return MSPC_ERRCODE(TIMEOUT_ERR);
        }
        ready = mspc_check_ready();
    }
    return MSPC_OK;
}

int32_t mspc_wait_native_ready(uint32_t timeout)
{
    return mspc_wait_state(MSPC_STATE_NATIVE_READY, timeout);
}

void mspc_set_access_flag(void)
{
    __ipc_smc_switch(TEE_MSPC_SET_ACCESS);
}

void mspc_clear_access_flag(void)
{
    __ipc_smc_switch(TEE_MSPC_CLR_ACCESS);
}

int32_t mspc_power_init(void)
{
    int32_t ret;

    ret = pthread_mutex_init(&g_power_mutex, NULL);
    if (ret != SRE_OK) {
        tloge("MSPC: Create power mutex lock failed! ret=%d\n", ret);
        return MSPC_POWER_MUTEX_ERR;
    }

    return MSPC_OK;
}

uint32_t mspc_power_fac_mode_entry(uint32_t reserved)
{
    int32_t ret;
    volatile uint64_t vote_status;

    UNUSED(reserved);
    (void)pthread_mutex_lock(&g_power_mutex);
    mspc_set_vote_status(MSPC_FACTORY_VOTE_ID, MSPC_VOTE_OFF);

    vote_status = mspc_get_vote_status();
    if (vote_status != MSPC_VOTE_STATUS_OFF) {
        ret = MSPC_ERRCODE(CHECK_FAC_MODE_ERR);
        goto exit;
    }
    /* Power off mspc */
    ret = __ipc_smc_switch(TEE_MSPC_POWER_OFF);
    if (ret != MSPC_OK) {
        tloge("%s: power off mspc failed: %d\n", __func__, ret);
        goto exit;
    }

    g_mspc_fac_mode = MSPC_IS_FACTORY_MODE;

exit:
    (void)pthread_mutex_unlock(&g_power_mutex);
    return ret;
}

uint32_t mspc_power_fac_mode_exit(uint32_t reserved)
{
    int32_t ret;

    UNUSED(reserved);
    (void)pthread_mutex_lock(&g_power_mutex);
    /* Power off mspc */
    ret = __ipc_smc_switch(TEE_MSPC_POWER_OFF);
    if (ret != MSPC_OK) {
        tloge("%s: power off mspc failed: %d\n", __func__, ret);
        goto exit;
    }
    g_mspc_fac_mode = MSPC_IS_NOT_FACTORY_MODE;
exit:
    (void)pthread_mutex_unlock(&g_power_mutex);
    return ret;
}

int32_t mspc_power_suspend(void)
{
    int32_t ret;
    uint64_t vote_status;

    (void)pthread_mutex_lock(&g_power_mutex);

    vote_status = mspc_get_vote_status();
    if (vote_status != MSPC_VOTE_STATUS_OFF) {
        tloge("%s: mspc is power on! Power off it! vote_status = 0x%llx\n",
              __func__, vote_status);
        mspc_clear_vote_status();
        ret = __ipc_smc_switch(TEE_MSPC_POWER_OFF);
        if (ret != MSPC_OK)
            tloge("%s:Power off mspc failed:%d!\n", __func__, ret);
    }

    /* If timer exist, destroy it. */
    if (g_mspc_timer) {
        tloge("%s: mspc timer! Power off it!\n", __func__);
        ret = __SRE_TimerEventStop(g_mspc_timer);
        if (ret != SRE_OK)
            tloge("%s: stop timer :%d\n", __func__, ret);
        ret = __SRE_TimerEventDestroy(g_mspc_timer);
        if (ret != SRE_OK)
            tloge("%s: destroy timer failed:%d\n", __func__, ret);
        else
            g_mspc_timer = NULL;

        ret = __ipc_smc_switch(TEE_MSPC_POWER_OFF);
        if (ret != MSPC_OK)
            tloge("%s:Power off mspc failed:%d!\n", __func__, ret);
    }

    (void)pthread_mutex_unlock(&g_power_mutex);
    return MSPC_OK;
}

void mspc_power_status_dump(void)
{
    uint64_t vote_status;

    vote_status = mspc_get_vote_status();
    tloge("%s: vote status:%llx\n", __func__, vote_status);
}
