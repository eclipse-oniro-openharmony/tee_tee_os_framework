/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cc power up or down
 * Create: 2019-11-26
 */

#include "cc_power.h"
#include <pthread.h>
#include <ipc_call.h>
#include <securec.h>
#include <sre_log.h>
#include <sre_dev_relcb.h>

#define PWR_SUCCESS 0
#if defined(CC_POWER_IN_SECOS)

#define ACCESS_REGISTER_FN_MAIN_ID    0xC500AA01
#define SECS_POWER_UP    0xAA55A5A5
#define SECS_POWER_DOWN  0x55AA5A5A
#define SECS_SECCLK_EN   0x5A5A55AA
#define SECS_SECCLK_DIS  0xA5A5AA55
#define SECS_COUNT_CLEAR 0xA5A5AAAA
#define ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL   0x55BBCCF0UL


static unsigned long g_secs_power_ctrl_count;
static bool g_secs_suspend_flag = false;
static pthread_mutex_t g_secs_count_lock;

static int32_t smc_atf(uint32_t smc_fid, kcall_tee_smc_atf_t *info)
{
    int32_t ret;
    ret = __smc_switch_to_atf(smc_fid, info);
    if (ret != PWR_SUCCESS)
        tloge("smc to atf failed, ret=0x%x\n", ret);
    return ret;
}

static void clear_atf_count(void)
{
    int32_t ret;
    kcall_tee_smc_atf_t info;

    info.x1 = SECS_COUNT_CLEAR;
    info.x2 = 0;
    info.x3 = ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL;
    info.x4 = 0;

    ret = smc_atf(ACCESS_REGISTER_FN_MAIN_ID, &info);
    if (ret != PWR_SUCCESS)
        tloge("secs count clear failed, ret =0x%x\n", ret);
}

void set_secs_suspend_flag(void)
{
    (void)pthread_mutex_lock(&g_secs_count_lock);
    if (g_secs_power_ctrl_count > 0) {
        g_secs_suspend_flag = true;
        tloge("secs is power down in suspend\n");
        clear_atf_count();
    }
    (void)pthread_mutex_unlock(&g_secs_count_lock);
}

int32_t secs_power_on(void)
{
    int32_t ret;
    kcall_tee_smc_atf_t info;

    (void)pthread_mutex_lock(&g_secs_count_lock);
    if (g_secs_power_ctrl_count != 0 && !g_secs_suspend_flag) {
        g_secs_power_ctrl_count++;
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return PWR_SUCCESS;
    }

    info.x1 = SECS_POWER_UP;
    info.x2 = 0;
    info.x3 = ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL;
    info.x4 = 0;
    ret = smc_atf(ACCESS_REGISTER_FN_MAIN_ID, &info);
    if (ret != PWR_SUCCESS) {
        tloge("secs power on failed, count = 0x%lx\n", g_secs_power_ctrl_count);
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return ret;
    }

    info.x1 = SECS_SECCLK_EN;
    info.x2 = 0;
    info.x3 = ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL;
    info.x4 = 0;
    ret = smc_atf(ACCESS_REGISTER_FN_MAIN_ID, &info);
    if (ret != PWR_SUCCESS) {
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        tloge("secs clk enable failed, count = 0x%lx\n", g_secs_power_ctrl_count);
        return ret;
    }

    if (g_secs_suspend_flag)
        g_secs_suspend_flag = false;
    g_secs_power_ctrl_count++;
    (void)pthread_mutex_unlock(&g_secs_count_lock);

    return ret;
}

int32_t secs_power_down(void)
{
    int32_t ret;
    (void)pthread_mutex_lock(&g_secs_count_lock);
    if (g_secs_power_ctrl_count == 0) {
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return PWR_SUCCESS;
    }

    if (g_secs_power_ctrl_count > 1) {
        g_secs_power_ctrl_count--;
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return PWR_SUCCESS;
    }

    kcall_tee_smc_atf_t info;

    info.x1 = SECS_SECCLK_DIS;
    info.x2 = 0;
    info.x3 = ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL;
    info.x4 = 0;
    ret = smc_atf(ACCESS_REGISTER_FN_MAIN_ID, &info);
    if (ret != PWR_SUCCESS) {
        tloge("secs disbale clk failed, count = 0x%lx\n", g_secs_power_ctrl_count);
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return ret;
    }

    info.x1 = SECS_POWER_DOWN;
    info.x2 = 0;
    info.x3 = ACCESS_REGISTER_FN_SUB_ID_SECS_POWER_CTRL;
    info.x4 = 0;
    ret = smc_atf(ACCESS_REGISTER_FN_MAIN_ID, &info);
    if (ret != PWR_SUCCESS) {
        tloge("secs power down failed, count = 0x%x\n", g_secs_power_ctrl_count);
        (void)pthread_mutex_unlock(&g_secs_count_lock);
        return ret;
    }
    g_secs_power_ctrl_count--;
    (void)pthread_mutex_unlock(&g_secs_count_lock);
    return ret;
}
#else
void set_secs_suspend_flag(void)
{
    tlogd("secs not set suspend flag\n");
}
int32_t secs_power_on(void)
{
    return PWR_SUCCESS;
}
int secs_power_down(void)
{
    return PWR_SUCCESS;
}
#endif

int32_t cc_power_release_cb(void *data)
{
    (void)data;
    return cc_power_down();
}

int32_t cc_power_on(void)
{
    int32_t power_ret;
    int32_t ret;
    power_ret = secs_power_on();
    if (power_ret != PWR_SUCCESS) {
        tloge("secs power on failed\n");
        return power_ret;
    }

    ret = (int32_t)task_register_devrelcb((DEV_RELEASE_CALLBACK)cc_power_release_cb, NULL);
    if (ret != PWR_SUCCESS) {
        tloge("register cb for cc power failed\n");
        power_ret = secs_power_down();
        if (power_ret != PWR_SUCCESS) {
            tloge("sec power down failed\n");
            return power_ret;
        }
    }
    return PWR_SUCCESS;
}

int32_t cc_power_down(void)
{
    int32_t res;

    (void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)cc_power_release_cb, NULL);
    res = secs_power_down();
    if (res != PWR_SUCCESS)
        tloge("secs power down failed\n");
    return res;
}
