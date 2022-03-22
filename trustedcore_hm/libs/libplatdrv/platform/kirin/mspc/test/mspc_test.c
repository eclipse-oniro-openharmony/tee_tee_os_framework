/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Test driver for MSP core.
 * Create: 2020/01/14
 */

#include <mspc_test.h>
#include <hmlog.h>
#include "msp_ta_channel.h"
#include <mspc.h>
#include <mspc_api.h>
#include <mspc_errno.h>
#include <mspc_power.h>
#include <se_hal.h>
#include <sre_sys.h>
#include <stdlib.h>
#include <tee_log.h>
#include <timer_export.h>

#define MSPC_TEST_PARAM_LEN       3
#define MSPC_TEST_MAX_LEN         (5 * 1024) /* 5KB */
#define MSPC_TEST_WORD_LEN        4
#define MSPC_SHORT_APDU_LEN       256
#define MSPC_LONG_APDU_LEN        MSPC_TEST_MAX_LEN
#define MSPC_POWER_TEST_DELAY     1000 /* 1s */
#define MSPC_TEST_INIT            0x5A
#define MSPC_PERFORMANCE_TIMEOUT  1 /* 1s */
#define S_TO_MS                   1000
#define MS_TO_NS                  1000000

#define UNUSED(x) ((void)(x))

enum mspc_test_cmd {
    MSPC_POWER_ON_TEST = 1,
    MSPC_POWER_OFF_TEST,
    MSPC_APDU_SHORT_DATA_TEST,
    MSPC_APDU_LONG_DATA_TEST,
    MSPC_APDU_RECEIVE_TEST,
    MSPC_CONNECT_TEST,
    MSPC_DISCONNECT_TEST,
    MSPC_POWER_TEST = 10,
    MSPC_BOOT_PERF_TEST,
};

struct mspc_test_table {
    enum mspc_test_cmd cmd;
    int32_t (*handle)(uint32_t params);
};

static uint32_t g_apdu_data[MSPC_TEST_MAX_LEN / MSPC_TEST_WORD_LEN];
static void mspc_apdu_test_init(uint32_t value)
{
    uint32_t i;

    for (i = 0; i < MSPC_TEST_MAX_LEN / MSPC_TEST_WORD_LEN; i++)
        g_apdu_data[i] = value + i; /* Donnot care overflow. */
}

static int32_t mspc_apdu_test_check_result(uint32_t size)
{
    uint32_t i;

    for (i = 0; i < size / MSPC_TEST_WORD_LEN; i++) {
        if (g_apdu_data[i] != (i + MSPC_TEST_INIT)) {
            tloge("mspc error: exp:0x%x, readl:0x%x\n",
                  i + MSPC_TEST_INIT, g_apdu_data[i]);
            return MSPC_ERROR;
        }
    }
    return MSPC_OK;
}

static int32_t mspc_test_connect(uint32_t vote_id)
{
    uint32_t p_atr = 0;
    uint32_t len = 0;
    int32_t ret;

    ret = mspc_connect(vote_id, &p_atr, &len);
    if (ret != MSPC_OK)
        tloge("%s:test failed!\n", __func__);
    return ret;
}

static int32_t mspc_test_disconnect(uint32_t vote_id)
{
    int32_t ret;

    ret = mspc_disconnect(vote_id);
    if (ret != MSPC_OK)
        tloge("%s:test failed!\n", __func__);
    return ret;
}

static int32_t mspc_apdu_short_data_test(uint32_t param)
{
    int32_t ret;
    const uint32_t size = MSPC_SHORT_APDU_LEN;

    mspc_apdu_test_init(param);
    ret = scard_send(0, (uint8_t *)g_apdu_data, size);
    if (ret != MSPC_OK)
        tloge("%s:test short apdu failed!\n", __func__);
    return ret;
}

static int32_t mspc_apdu_long_data_test(uint32_t param)
{
    int32_t ret;
    const uint32_t size = MSPC_LONG_APDU_LEN;

    mspc_apdu_test_init(param);
    ret = scard_send(0, (uint8_t *)g_apdu_data, size);
    if (ret != MSPC_OK)
        tloge("%s:test long apdu failed!\n", __func__);
    return ret;
}

static int32_t mspc_apdu_receive_test(uint32_t param)
{
    int32_t ret;
    uint32_t size = MSPC_TEST_MAX_LEN;

    UNUSED(param);
    ret = scard_receive((uint8_t *)g_apdu_data, &size);
    if (ret != MSPC_OK) {
        tloge("%s:test receive apdu failed!\n", __func__);
        return ret;
    }

    tloge("mspc receive size is 0x%x\n", size);
    ret = mspc_apdu_test_check_result(size);
    if (ret != MSPC_OK)
        tloge("%s:check apdu failed!\n", __func__);

    return ret;
}

static int32_t mspc_power_test(uint32_t loop)
{
    int32_t ret;
    uint32_t i, j;

    for (i = 0; i < loop; i++) {
        tloge("%s: loop:%u\n", __func__, i);
        for (j = 0; j < MSPC_MAX_VOTE_ID; j++) {
            tloge("%s: vote id %u\n", __func__, j);
            ret = mspc_power_on(j);
            if (ret != MSPC_OK) {
                tloge("mspc power on failed!\n");
                goto exit;
            }
            SRE_DelayMs(MSPC_POWER_TEST_DELAY); /* 1s */
            ret = mspc_power_off(j);
            if (ret != MSPC_OK) {
                tloge("mspc power off failed!\n");
                goto exit;
            }
            SRE_DelayMs(MSPC_POWER_TEST_DELAY); /* 1s */
        }
    }
    tloge("%s:test end!\n", __func__);
    return MSPC_OK;
exit:
    return ret;
}

static int32_t mspc_boot_performance_test(uint32_t param)
{
    int32_t ret;
    struct timespec start_ts = {0};
    struct timespec end_ts = {0};
    int32_t diff;

    UNUSED(param);
    clock_gettime(CLOCK_REALTIME, &start_ts);
    ret = mspc_power_on(MSPC_SECFLASH_VOTE_ID);
    if (ret != MSPC_OK) {
        tloge("%s power on failed\n", __func__);
        return ret;
    }

    ret = mspc_wait_native_ready(MSPC_PERFORMANCE_TIMEOUT);
    if (ret != MSPC_OK) {
        tloge("%s wait_native_ready failed\n", __func__);
        (void)mspc_power_off(MSPC_SECFLASH_VOTE_ID);
        return ret;
    }
    clock_gettime(CLOCK_REALTIME, &end_ts);
    diff = (end_ts.tv_sec - start_ts.tv_sec) * S_TO_MS + (end_ts.tv_nsec / MS_TO_NS) - (start_ts.tv_nsec / MS_TO_NS);
    tloge("%s mspc boot spend %d ms\n", __func__, diff);

    ret = mspc_power_off(MSPC_SECFLASH_VOTE_ID);
    if (ret != MSPC_OK) {
        tloge("%s power off failed\n", __func__);
        return ret;
    }

    return MSPC_OK;
}

struct mspc_test_table g_mspc_test_table[] = {
    { MSPC_POWER_ON_TEST, mspc_power_on },
    { MSPC_POWER_OFF_TEST, mspc_power_off },
    { MSPC_APDU_SHORT_DATA_TEST, mspc_apdu_short_data_test },
    { MSPC_APDU_LONG_DATA_TEST, mspc_apdu_long_data_test },
    { MSPC_APDU_RECEIVE_TEST, mspc_apdu_receive_test },
    { MSPC_CONNECT_TEST, mspc_test_connect },
    { MSPC_DISCONNECT_TEST, mspc_test_disconnect },
    { MSPC_POWER_TEST, mspc_power_test },
    { MSPC_BOOT_PERF_TEST, mspc_boot_performance_test },
};

uint32_t mspc_driver_test(const struct msp_chan_parms *chan_parms)
{
    char *param[MSPC_TEST_PARAM_LEN] = {0};
    uint32_t argv[MSPC_TEST_PARAM_LEN] = {0};
    uint32_t i;
    int32_t ret;

    if (!chan_parms) {
        tloge("%s:Invalid input!\n", __func__);
        return MSPC_ERROR;
    }

    for (i = 0; i < MSPC_TEST_PARAM_LEN; i++) {
        /* parm[0] is func name:"mspc_driver_test" */
        param[i] = (char *)&(chan_parms->parm[i + 1]);
        argv[i] = (uint32_t)atoi(param[i]);
        tloge("%s: argv %d is %u\n", __func__, i, argv[i]);
    }

    for (i = 0; i < ARRAY_SIZE(g_mspc_test_table); i++) {
        if (argv[0] == g_mspc_test_table[i].cmd) {
            ret = g_mspc_test_table[i].handle(argv[1]);
            break;
        }
    }
    if (i >= ARRAY_SIZE(g_mspc_test_table)) {
        tloge("%s:Invalid index:%d!\n", __func__, argv[0]);
        ret = MSPC_ERROR;
    }
    if (ret == MSPC_OK)
        ret = MSP_TA_CHANNEL_OK;
    return ret;
}

uint32_t mspc_test_callback_init(void)
{
    uint32_t ret;

    ret = msp_chan_rgst_ecall_func("mspc_driver_test", mspc_driver_test);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    return MSPC_OK;
}
