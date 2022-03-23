/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: for seplat data_link test.
 * Create: 2021/01/12
 */

#include "seplat_dl_test_entry.h"
#include "dl_test.h"
#include "seplat_common.h"
#include "seplat_errno.h"
#include "stdint.h"
#include "hmlog.h"
#include "msp_ta_channel.h"
#include "se_hal.h"
#include "sre_sys.h"
#include "stdlib.h"
#include "tee_log.h"

#define SEPLAT_THIS_MODULE SEPLAT_MODULE_DL_TEST
#define SEPLAT_ERROR_TAG "[SEPLAT_DL_TEST]"

#define DL_TEST_PARAM_LEN       3

uint32_t dl_driver_test(const struct msp_chan_parms *chan_parms)
{
    char *param[DL_TEST_PARAM_LEN] = {0};
    uint32_t argv[DL_TEST_PARAM_LEN] = {0};
    uint32_t i;
    int32_t ret;

    if (!chan_parms) {
        SEPLAT_PRINT("%s:Invalid input!\n", __func__);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_CHAN_PARAM_NULL);
    }

    for (i = 0; i < DL_TEST_PARAM_LEN; i++) {
        /* parm[0] is func name:"mspc_driver_test" */
        param[i] = (char *)&chan_parms->parm[i + 1];
        argv[i] = (uint32_t)atoi(param[i]);
        SEPLAT_PRINT("%s: argv %d is %u\n", __func__, i, argv[i]);
    }

    ret = dl_test_entry(argv[0], argv[1]);
    if (ret != SEPLAT_OK) {
        SEPLAT_PRINT("%s:error:%d!\n", __func__, ret);
        return ret;
    }
    return MSP_TA_CHANNEL_OK;
}

uint32_t dl_test_callback_init(void)
{
    uint32_t ret;

    ret = msp_chan_rgst_ecall_func("dl_driver_test", dl_driver_test);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    return SEPLAT_OK;
}
