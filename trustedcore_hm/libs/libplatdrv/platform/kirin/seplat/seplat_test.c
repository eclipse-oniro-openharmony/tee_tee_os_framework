/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:Test for seplat drivers.
 * Create: 2021/02/02
 */

#include "seplat_test.h"
#include "seplat_common.h"
#include "seplat_errno.h"
#include "seplat_power.h"
#include "seplat_status.h"
#include <msp_ta_channel.h>
#include <stdlib.h>
#include <types.h>

#define SEPLAT_TEST_PARAM_LEN       4
#define SEPLAT_TEST_ERROR           (0xA5A5)

enum {
    SEPLAT_POWER_TEST           = 0,
    SEPLAT_STATUS_TEST          = 1,
};

enum {
    ARGS_INDEX0    = 0,
    ARGS_INDEX1    = 1,
    ARGS_INDEX2    = 2,
    ARGS_INDEX3    = 3,
    ARGS_INDEX4    = 4,
};

struct seplat_test_table {
    uint32_t cmd;
    uint32_t (*handle)(uint32_t x1, uint32_t x2, uint32_t x3);
};

static uint32_t seplat_test_status(uint32_t x1, uint32_t x2, uint32_t x3);

struct seplat_test_table g_seplat_test_table[] = {
    { SEPLAT_POWER_TEST,  seplat_power_process },
    { SEPLAT_STATUS_TEST, seplat_test_status },
};

static uint32_t seplat_test_status(uint32_t x1, uint32_t x2, uint32_t x3)
{
    uint32_t status;

    (void)x1;
    (void)x2;
    (void)x3;

    status = seplat_get_dts_status();
    if (status == (uint32_t)SEPLAT_DTS_EXIST)
        return SEPLAT_OK;
    return SEPLAT_TEST_ERROR;
}

uint32_t seplat_driver_test(const struct msp_chan_parms *chan_parms)
{
    char *param[SEPLAT_TEST_PARAM_LEN] = {0};
    uint32_t argv[SEPLAT_TEST_PARAM_LEN] = {0};
    uint32_t i;
    uint32_t ret = SEPLAT_TEST_ERROR;

    if (!chan_parms) {
        SEPLAT_PRINT("%s:Invalid input!\n", __func__);
        return ret;
    }

    for (i = 0; i < SEPLAT_TEST_PARAM_LEN; i++) {
        /* chan_parms->param[0] is func name:"seplat_driver_test" */
        param[i] = (char *)&(chan_parms->parm[i + 1]);
        argv[i] = (uint32_t)atoi(param[i]);
        SEPLAT_PRINT("%s: argv %d is %u\n", __func__, i, argv[i]);
    }

    for (i = 0; i < ARRAY_SIZE(g_seplat_test_table); i++) {
        if (argv[0] == g_seplat_test_table[i].cmd) {
            ret = g_seplat_test_table[i].handle(argv[ARGS_INDEX1],
                    argv[ARGS_INDEX2], argv[ARGS_INDEX3]);
            break;
        }
    }
    if (i >= ARRAY_SIZE(g_seplat_test_table)) {
        SEPLAT_PRINT("%s:Invalid index:%d!\n", __func__, argv[ARGS_INDEX0]);
        ret = SEPLAT_TEST_ERROR;
    }
    if (ret == SEPLAT_OK)
        ret = MSP_TA_CHANNEL_OK;
    return ret;
}

uint32_t seplat_test_callback_init(void)
{
    uint32_t ret;

    ret = msp_chan_rgst_ecall_func("seplat_driver_test", seplat_driver_test);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    return SEPLAT_OK;
}
