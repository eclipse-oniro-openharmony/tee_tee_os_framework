/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: TUI tp panel common driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */
#include "tui_touchscreen_panel.h"
#include <stdlib.h>
#include <stdio.h>
#include "securec.h"
#include "sre_hwi.h"
#include "drv_fwk.h"
#include <ipc_call.h>
#include "tui_touchscreen.h"
#include "tui_touchscreen_platform.h"

static struct ts_ops ts_fn_list[] = {
    { IC_THP_BOE_SYNA_OCE, THP_SYNA_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_BOE_GDIX_OCE, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_VIS_SYNA_YOR, THP_SYNA_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_VIS1_SYNA_YOR, THP_SYNA_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_BOE_SYNA_YOR, THP_GOODIX_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_BOE1_SYNA_YOR, THP_SYNA_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_TIANMA_SYNA_YOR, THP_GOODIX_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_TIANMA1_SYNA_YOR, THP_GOODIX_DEVICE, ts_syna_init, ts_syna_get_frame, ts_syna_exit },
    { IC_THP_BOE_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_BOE1_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_BOE2_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_BOE3_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_VIS_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_VIS1_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_VIS2_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
    { IC_THP_VIS3_GDIX_YOR, THP_GOODIX_DEVICE, ts_goodix_init, ts_goodix_get_frame, ts_goodix_exit },
};

struct ts_ops *get_cur_ts_ops_data(unsigned int *size)
{
    *size = sizeof(ts_fn_list) / sizeof(ts_fn_list[0]);
    return ts_fn_list;
}
