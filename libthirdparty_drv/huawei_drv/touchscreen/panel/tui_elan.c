/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: elan driver
 * Author: lijie
 * Create: 2017-04-02
 */
#include "sre_sys.h"
#include <legacy_mem_ext.h>
#include <mem_ops.h>
#include "i2c.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"
#include "hisi_tui_touchscreen.h"
#include <string.h>

#define REPORT_DATA_LEN 26
#define REPORT_ID_BYTE 2
#define FINGER_REPORT_ID 0x01
#define PEN_REPORT_ID 0x07
#define CUR_FINGER_NUM_BYTE 25
#define MAX_FINGER_SIZE 10
#define POINT_HEAD_LEN 3

#define FINGERX_POINT_HBYTE 8
#define FINGERX_POINT_LBYTE 7
#define FINGERY_POINT_HBYTE 10
#define FINGERY_POINT_LBYTE 9

#define PENX_POINT_HBYTE 5
#define PENX_POINT_LBYTE 4
#define PENY_POINT_HBYTE 7
#define PENY_POINT_LBYTE 6
#define PEN_PRESS_HBYTE 9
#define PEN_PRESS_LBYTE 8

#define FINGER_PRESSURE 255
#define FINGER_MAJOR 100
#define FINGER_MINOR 100
#define VALUE_OFFSET 11
#define TEN_FINGER_DATA_LEN 115

#define FINGER_OSR 64
#define PEN_OSR 260
#define PROJECT_ID_MAX_LEN 11
#define ELAN_I2C_ADDR 0x10
#define PEN_TIP_STATUS_OFFSET 3
#define START_STEP 1
#define ELAN_RET_ERROR 1

enum elan_mt_flags {
    ELAN_MT_FLAG_FLIP = 0x08,  /* x,y exchange */
    ELAN_MT_FLAG_INV_X = 0x10, /* overturn x */
    ELAN_MT_FLAG_INV_Y = 0x20, /* overturn y */
};

struct elan_ts_info {
    char project_id[PROJECT_ID_MAX_LEN];
    unsigned int mt_flags;
    int tx_num;
    int rx_num;
    int finger_x_resolution; /* (tx_num-1) * FINGER_OSR */
    int finger_y_resolution; /* (rx_num-1) * FINGER_OSR */
    int pen_x_resolution;
    int pen_y_resolution;
    int lcm_max_x;
    int lcm_max_y;
};

struct elan_ts_info g_elan_ts_info;
struct elan_ts_info elan_ts_info_list[] = {
  { IC_ELAN_SCM_OFILM, 0x18, 36, 56, 0, 0, 0, 0, 1600, 2560, },
  { IC_ELAN_SCM_TOPTOUCH, 0x18, 36, 56, 0, 0, 0, 0, 1600, 2560, },
};

static int elan_ktf_ts_recv_data(u8 *pbuf, struct ts_tui_fingers *info)
{
    int ret;
    int finger_num;
    int recv_count;
    int recv_count_max;
    u8 *buf = pbuf;
    u8 data_buf[REPORT_DATA_LEN] = {0};

    if ((buf == NULL) || (info == NULL)) {
        TP_LOG_ERR("[elan]%s:arg is NULL\n", __func__);
        return -EINVAL;
    }
    ret = ts_tui_i2c_read_directly(buf, REPORT_DATA_LEN, ELAN_I2C_ADDR);
    if (ret) {
        TP_LOG_ERR("[elan]elan_i2c_read Fail!ret=%d\n", ret);
        return ret;
    }

    if (buf[REPORT_ID_BYTE] == FINGER_REPORT_ID) {
        finger_num = buf[CUR_FINGER_NUM_BYTE];
        if (finger_num > MAX_FINGER_SIZE) {
            TP_LOG_ERR("[elan]:invalid finger num\n");
            return -EINVAL;
        }
        info->cur_finger_number = finger_num;
        /* 2, one recv_package include 2 fingers touch mesg */
        recv_count_max = (finger_num / 2) + ((finger_num % OFFSET_BYTE2) != 0);
        for (recv_count = START_STEP; recv_count < recv_count_max; recv_count++) {
            ret = ts_tui_i2c_read_directly(data_buf, REPORT_DATA_LEN, 0x10);
            if (ret) {
                TP_LOG_ERR("[elan]elan_i2c_read Fail!ret=%d\n", ret);
                return ret;
            }
            ret = memcpy_s((void *)(buf + (REPORT_DATA_LEN - 1) * recv_count - POINT_HEAD_LEN * (recv_count - 1)),
                REPORT_DATA_LEN - POINT_HEAD_LEN, (void *)(data_buf + POINT_HEAD_LEN),
                REPORT_DATA_LEN - POINT_HEAD_LEN);
            if (ret != 0) {
                TP_LOG_ERR("[elan]elan_i2c_read memcpy Fail!ret=%d\n", ret);
                return ret;
            }
        }
    }
    return NO_ERR;
}

static void elan_mt_process_touch(uint16_t *x, uint16_t *y, int x_resolution, int y_resolution)
{
    uint16_t temp_value;
    uint16_t temp_x = *x;
    uint16_t temp_y = *y;
    int lcm_max_x;
    int lcm_max_y;

    if (g_elan_ts_info.mt_flags & ELAN_MT_FLAG_FLIP) {
        temp_value = temp_x;
        temp_x = temp_y;
        temp_y = temp_value;
    }
    lcm_max_x = g_elan_ts_info.lcm_max_x;
    lcm_max_y = g_elan_ts_info.lcm_max_y;
    if ((x_resolution > 0) && (y_resolution > 0)) {
        temp_x = (uint16_t)((int)temp_x * lcm_max_x / x_resolution);
        temp_y = (uint16_t)((int)temp_y * lcm_max_y / y_resolution);
    }

    if (g_elan_ts_info.mt_flags & ELAN_MT_FLAG_INV_X)
        temp_x = lcm_max_x - temp_x;
    if (g_elan_ts_info.mt_flags & ELAN_MT_FLAG_INV_Y)
        temp_y = lcm_max_y - temp_y;

    *x = temp_x;
    *y = temp_y;
}

static void elan_ktf_finger_parse_xy(uint8_t *data, uint16_t *x, uint16_t *y)
{
    *x = data[FINGERX_POINT_HBYTE];
    *x <<= OFFSET_BYTE8; /* shift left one byte */
    *x |= data[FINGERX_POINT_LBYTE];

    *y = data[FINGERY_POINT_HBYTE];
    *y <<= OFFSET_BYTE8; /* shift left one byte */
    *y |= data[FINGERY_POINT_LBYTE];
}

static void parse_fingers_point(struct ts_tui_fingers *pointinfo, u8 *pbuf)
{
    int i;
    int fid;
    int idx = 3; /* point  start byte */
    uint16_t x = 0;
    uint16_t y = 0;
    int finger_num = 0;

    if ((pointinfo == NULL) || (pbuf == NULL)) {
        TP_LOG_ERR("[elan]%s:arg is NULL\n", __func__);
        return;
    }

    for (i = 0; i < pointinfo->cur_finger_number; i++) {
        if ((pbuf[idx] & 0x3) != 0x0) {               /* bit0 tip bit1 range */
            fid = (pbuf[idx] >> OFFSET_BYTE2) & 0x3f; /* fingerid bit 2-7 */
            elan_ktf_finger_parse_xy(pbuf + idx, &x, &y);
            elan_mt_process_touch(&x, &y, g_elan_ts_info.finger_x_resolution, g_elan_ts_info.finger_y_resolution);
            pointinfo->fingers[fid].status = TS_FINGER_PRESS;
            pointinfo->fingers[fid].x = (int)x;
            pointinfo->fingers[fid].y = (int)y;
            pointinfo->fingers[fid].major = FINGER_MAJOR;
            pointinfo->fingers[fid].minor = FINGER_MINOR;
            pointinfo->fingers[fid].pressure = FINGER_PRESSURE;
            finger_num++;
        }
        idx += VALUE_OFFSET;
    }
    pointinfo->cur_finger_number = finger_num;
}

static inline void elan_ktf_pen_parse_xy(uint8_t *data, uint16_t *x, uint16_t *y, uint16_t *p)
{
    *x = ((data[PENX_POINT_HBYTE] << OFFSET_BYTE8) | /* shif left one byte */
        data[PENX_POINT_LBYTE]);
    *y = ((data[PENY_POINT_HBYTE] << OFFSET_BYTE8) | /* shif left one byte */
        data[PENY_POINT_LBYTE]);
    *p = ((data[PEN_PRESS_HBYTE] << OFFSET_BYTE8) | /* shif left one byte */
        data[PEN_PRESS_LBYTE]);
}

static void parse_pen_point(struct ts_tui_fingers *pointinfo, u8 *pbuf)
{
    unsigned int pen_down;
    uint16_t x = 0;
    uint16_t y = 0;
    uint16_t p = 0;

    if ((pointinfo == NULL) || (pbuf == NULL)) {
        TP_LOG_ERR("[elan]%s:arg is NULL\n", __func__);
        return;
    }

    /* pbuf[3] bit 0,1 tip and inrange */
    pen_down = pbuf[PEN_TIP_STATUS_OFFSET] & 0x03;
    if (pen_down) {
        elan_ktf_pen_parse_xy(pbuf, &x, &y, &p);
        elan_mt_process_touch(&x, &y, g_elan_ts_info.pen_x_resolution, g_elan_ts_info.pen_y_resolution);
        pointinfo->fingers[0].status = TS_FINGER_PRESS;
        pointinfo->fingers[0].x = (int)x;
        pointinfo->fingers[0].y = (int)y;
        pointinfo->fingers[0].pressure = (int)p;
    }
    pointinfo->cur_finger_number = (int)(pen_down >> 1);
}


int elan_get_data(struct ts_tui_fingers *report_data)
{
    int ret;
    struct ts_tui_fingers *info = NULL;
    u8 buf[TEN_FINGER_DATA_LEN] = {0};

    if (report_data == NULL)
        return -ELAN_RET_ERROR;

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return -ELAN_RET_ERROR;
    }

    memset_s((void *)info, sizeof(struct ts_tui_fingers), 0, sizeof(struct ts_tui_fingers));

    ret = elan_ktf_ts_recv_data(buf, info);
    if (ret != NO_ERR) {
        TP_LOG_ERR("Failed to recv data!\n");
        SRE_MemFree(0, info);
        return -ELAN_RET_ERROR;
    }
    if (buf[REPORT_ID_BYTE] == FINGER_REPORT_ID)
        parse_fingers_point(info, buf);
    else if (buf[REPORT_ID_BYTE] == PEN_REPORT_ID)
        parse_pen_point(info, buf);

    ret = ts_tui_algo_t1(info, report_data);
    if (ret != NO_ERR)
        TP_LOG_ERR("ts_tui_algo_t1 failed\n");
    SRE_MemFree(0, info);
    return ret;
}

static int elan_get_tp_info(char *project_id)
{
    unsigned int index;

    for (index = 0; index < (sizeof(elan_ts_info_list)) / (sizeof(g_elan_ts_info)); index++) {
        if (!strncmp(elan_ts_info_list[index].project_id, project_id, PROJECT_ID_MAX_LEN - 1)) {
            TP_LOG_ERR("elan device found\n");
            memcpy_s((void *)&g_elan_ts_info, sizeof(g_elan_ts_info), (void *)&elan_ts_info_list[index],
                sizeof(g_elan_ts_info));
            g_elan_ts_info.finger_x_resolution = (g_elan_ts_info.tx_num - 1) * FINGER_OSR;
            g_elan_ts_info.finger_y_resolution = (g_elan_ts_info.rx_num - 1) * FINGER_OSR;
            g_elan_ts_info.pen_x_resolution = (g_elan_ts_info.tx_num - 1) * PEN_OSR;
            g_elan_ts_info.pen_y_resolution = (g_elan_ts_info.rx_num - 1) * PEN_OSR;
            return 0;
        }
    }

    return -ELAN_RET_ERROR;
}

int elan_device_init(void)
{
    struct ts_info arg;
    int ret;

    memset_s((void *)(&arg), sizeof(arg), 0, sizeof(arg));
    ret = ts_ioctl(TS_GET_PRO_ID, (void *)(&arg));
    if (ret < 0)
        TP_LOG_ERR("ts_ioctl get project id failed\n");

    TP_LOG_ERR("projectid = %s\n", arg.ts_ioctl_data.project_id);
    ret = elan_get_tp_info(arg.ts_ioctl_data.project_id);
    if (ret < 0)
        TP_LOG_ERR("elan device init failed\n");
    else
        TP_LOG_ERR("elan device init success\n");

    return ret;
}
