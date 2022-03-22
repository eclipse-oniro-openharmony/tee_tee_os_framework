/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description:TUI tp panel common driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */
#ifndef _TUI_TOUCHSCREEN_PANEL_
#define _TUI_TOUCHSCREEN_PANEL_

#include "tui_touchscreen.h"

#define IC_THP_BOE_GDIX_OCE "P1729S1310"
#define IC_THP_BOE_SYNA_OCE "P172921341"

#define IC_THP_VIS_SYNA_YOR "B20Y922900"
#define IC_THP_VIS1_SYNA_YOR "B20Y922910"
#define IC_THP_BOE_SYNA_YOR "B20Y921300"
#define IC_THP_BOE1_SYNA_YOR "B20Y921310"
#define IC_THP_TIANMA_SYNA_YOR "B20Y921100"
#define IC_THP_TIANMA1_SYNA_YOR "B20Y921110"
#define IC_THP_BOE_GDIX_YOR "B20Y9S1300"
#define IC_THP_BOE1_GDIX_YOR "B20Y9S1310"
#define IC_THP_BOE2_GDIX_YOR "B20Y9S1301"
#define IC_THP_BOE3_GDIX_YOR "B20Y9S1311"
#define IC_THP_VIS_GDIX_YOR "B20Y9S2900"
#define IC_THP_VIS1_GDIX_YOR "B20Y9S2901"
#define IC_THP_VIS2_GDIX_YOR "B20Y9S2910"
#define IC_THP_VIS3_GDIX_YOR "B20Y9S2911"


enum touch_device_type {
    THP_JDI_DEVICE_VICTORIA = 11,
    THP_GOODIX_DEVICE = 12,
    THP_SYNA_DEVICE = 13,
    MAX_THP_DEVICE_NUM = 0xFFFF,
};

struct ts_ops {
    char device_name[THP_PROJECT_ID_LEN + 1];
    enum touch_device_type touch_device;
    int32_t (*fn_touch_init)(void);
    int32_t (*fn_get_data)(struct ts_tui_fingers *report_data);
    void (*fn_touch_exit)(void);
};

int32_t ts_goodix_init(void);
void ts_goodix_exit(void);
int32_t ts_goodix_get_frame(struct ts_tui_fingers *report_data);

int32_t ts_syna_get_frame(struct ts_tui_fingers *report_data);
int32_t ts_syna_init(void);
void ts_syna_exit(void);

/* tui platform interface */
struct ts_ops *get_cur_ts_ops_data(uint32_t *size);
#endif