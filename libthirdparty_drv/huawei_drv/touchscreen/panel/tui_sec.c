/*
 * sec thp tui driver
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: sec thp tui driver
 * Author: weizhenggui
 * Create: 2018-12-24
 */
#include <legacy_mem_ext.h> /* SRE_MemAlloc */
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"
#include "hisi_tui_touchscreen.h"

#define SEC_TS_READ_ONE_EVENT 0x60
#define SEC_TS_READ_ALL_EVENT 0x61
#define SEC_TS_CMD_CLEAR_EVENT_STACK 0x62

#define SEC_TS_COORDINATE_EVENT 0
#define MAX_SUPPORT_TOUCH_COUNT 10
#define MAX_SUPPORT_HOVER_COUNT 1
#define I2C_SEC_ADDR 0x17 /* sec-salve addr */
#define SEC_TS_EVENT_BUFF_SIZE 13
#define MAX_EVENT_COUNT 32
/* Number of Records(32) * Record Length(8bit) */
#define SEC_TOUCH_REPORT_MAX_SIZE (SEC_TS_EVENT_BUFF_SIZE * MAX_EVENT_COUNT)

#define SEC_TS_EVENT_CONTINUE 1
#define SEC_TS_EVENT_STOP 0

#define SEC_TS_TOUCHTYPE_NORMAL 0
#define SEC_TS_TOUCHTYPE_HOVER 1
#define SEC_TS_TOUCHTYPE_FLIPCOVER 2
#define SEC_TS_TOUCHTYPE_GLOVE 3
#define SEC_TS_TOUCHTYPE_PALM 5

#define SEC_TS_COORDINATE_ACTION_NONE 0
#define SEC_TS_COORDINATE_ACTION_PRESS 1
#define SEC_TS_COORDINATE_ACTION_MOVE 2
#define SEC_TS_COORDINATE_ACTION_RELEASE 3

#define Y761_I2C_SEC_ADDR 0x48
#define RVL_PANEL_RESOLUTION_X 1080
#define RVL_PANEL_RESOLUTION_Y 2220
#define RVL_TOUCH_FW_RESOLUTION_X 4096
#define RVL_TOUCH_FW_RESOLUTION_Y 4096

static int sec_slave_addr;

/* sec ic frame 8 byte */
struct sec_ts_event_coordinate {
    u8 eid : 2;
    u8 tid : 4;
    u8 tchsta : 2;
    u8 x_11_4;
    u8 y_11_4;
    u8 y_3_0 : 4;
    u8 x_3_0 : 4;
    u8 major;
    u8 minor;
    u8 z : 6;
    u8 ttype_3_2 : 2;
    u8 left_event : 6;
    u8 ttype_1_0 : 2;
    u8 wx;
    u8 wy;
    u8 ewx;
    u8 ewy;
    u8 orient;
} __attribute__((packed));

int sec_get_data(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char input_id;
    unsigned char event_id;
    unsigned char ttype;
    unsigned char action;
    unsigned char read_event_buff[MAX_EVENT_COUNT][SEC_TS_EVENT_BUFF_SIZE + 1] = { { 0 } };
    unsigned char *event_buff = NULL;
    struct sec_ts_event_coordinate *p_event_coord = NULL;
    struct ts_tui_fingers *info = NULL;
    int rec_num = 0;
    int remain_event = SEC_TS_EVENT_CONTINUE;

    if (report_data == NULL)
        return ERROR;

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return ERROR;
    }

    do {
        read_event_buff[0][0] = SEC_TS_READ_ONE_EVENT;
        ret = ts_tui_i2c_read(read_event_buff[0], SEC_TS_EVENT_BUFF_SIZE, sec_slave_addr);
        if (ret < 0) {
            TP_LOG_ERR("%s: i2c read one event failed\n", __func__);
            remain_event = SEC_TS_EVENT_STOP;
            continue;
        }

        event_buff = (unsigned char *)read_event_buff;
        /* empty event */
        if ((event_buff[0] == 0) && (event_buff[1] == 0)) {
            remain_event = SEC_TS_EVENT_STOP;
            continue;
        }
        event_id = event_buff[0] & 0x3;
        if (event_id != SEC_TS_COORDINATE_EVENT) {
            TP_LOG_ERR("%s: finger status: %d\n", __func__, event_id);
            remain_event = SEC_TS_EVENT_STOP;
            continue;
        }

        p_event_coord = (struct sec_ts_event_coordinate *)event_buff;
        input_id = (p_event_coord->tid - 1);
        rec_num++;
        if (input_id >= TOUCH_MAX_FINGER_NUM) {
            TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
            continue;
        }

        action = p_event_coord->tchsta;
        ttype = (p_event_coord->ttype_3_2 << OFFSET_BYTE2) | (p_event_coord->ttype_1_0 << 0);
        info->fingers[input_id].event = action;
        /* PATCH: Huawei does not use our event, they use x=0 or y=0 as this id lift off event */
        switch (action) {
        case SEC_TS_COORDINATE_ACTION_RELEASE:
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            rec_num--;
            break;
        case SEC_TS_COORDINATE_ACTION_PRESS:
        case SEC_TS_COORDINATE_ACTION_NONE:
        case SEC_TS_COORDINATE_ACTION_MOVE:
            info->fingers[input_id].x = (p_event_coord->x_11_4 << OFFSET_BYTE4) | (p_event_coord->x_3_0);
            info->fingers[input_id].y = (p_event_coord->y_11_4 << OFFSET_BYTE4) | (p_event_coord->y_3_0);
            /*
            * For the Ravel project, the resolution of the TP firmware is (4096, 4096),
            * but the resolution of the LCD is (1080, 2220).
            * In order to match the coordinates reported by the TP to the LCD,
            * it is necessary to convert the reporting coordinates of the TP.
            */
            if (sec_slave_addr == Y761_I2C_SEC_ADDR) {
                info->fingers[input_id].x =
                    info->fingers[input_id].x * RVL_PANEL_RESOLUTION_X / RVL_TOUCH_FW_RESOLUTION_X;
                info->fingers[input_id].y =
                    info->fingers[input_id].y * RVL_PANEL_RESOLUTION_Y / RVL_TOUCH_FW_RESOLUTION_Y;
            }
            break;
        default:
            break;
        }

        switch (ttype) { /* Detect the object type */
        case SEC_TS_TOUCHTYPE_NORMAL:
            info->fingers[input_id].status = FINGER_ENTER;
            break;
        case SEC_TS_TOUCHTYPE_GLOVE:
            info->fingers[input_id].status = GLOVE_TOUCH;
            break;
        case SEC_TS_TOUCHTYPE_FLIPCOVER:
        case SEC_TS_TOUCHTYPE_HOVER:
            info->fingers[input_id].status = FINGER_MOVING;
            break;
        default:
            break;
        }
        info->fingers[input_id].pressure = p_event_coord->z & 0x3F;
        info->fingers[input_id].major = p_event_coord->major;
        info->fingers[input_id].minor = p_event_coord->minor;
        info->fingers[input_id].orientation = p_event_coord->orient;
    } while (remain_event);

    info->cur_finger_number = rec_num;
    ts_tui_algo_t1(info, report_data);
    SRE_MemFree(0, info);
    return ret;
}

int sec_device_init(void)
{
    int chip_type;

    chip_type = hisi_tui_get_chip_type();
    TP_LOG_ERR("chip_type = %d\n", chip_type);
    if (chip_type == SEC_DEVICE_RAL)
        sec_slave_addr = Y761_I2C_SEC_ADDR;
    else
        sec_slave_addr = I2C_SEC_ADDR;
    TP_LOG_ERR("i2c addr:0x%2X\n", sec_slave_addr);
    TP_LOG_ERR("device_init:sec\n");
    return 0;
}
