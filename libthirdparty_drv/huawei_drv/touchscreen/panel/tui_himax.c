/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Himax driver
 * Author: lijie
 * Create: 2018-12-22
 */
#include <mem_ops.h>
#include "sre_sys.h"
#include "mem_page_ops.h"
#include "libhwsecurec/securec.h"
#include "tui_panel.h"
#include <platform_touchscreen.h>

extern int g_frame_max_len;
struct tee_thp_frame_buff __attribute__((weak)) g_tee_tp_buff;

#define DUMMY_DATA 2
#define REG_GET_FRAME_CMD 0x30
#define REG_GET_FRAME_CMD_HEAD 0xF3
#define REG_GET_FRAME_CMD_TAIL 0x00
#define HIMAX_FRAME_SIZE 1411

int ts_himax_init(void)
{
    TP_LOG_ERR("ts_himax_init\n");
    return 0;
}

int ts_himax_get_frame(struct ts_tui_fingers *report_data)
{
    unsigned int ret;
    unsigned char buff[MAX_FRAME_LEN + DUMMY_DATA] = {0};

    (void)report_data;
    buff[0] = REG_GET_FRAME_CMD_HEAD;
    buff[OFFSET_BYTE1] = REG_GET_FRAME_CMD; /* read command */
    buff[OFFSET_BYTE2] = REG_GET_FRAME_CMD_TAIL;
    ret = ts_spi_sync(HIMAX_FRAME_SIZE, &buff[0], &g_tee_tp_buff.revbuff[0]);
    if (ret != 0) {
        TP_LOG_ERR("ts_himax_get_frame ts_spi_sync error\n");
        return ERROR;
    }

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}
