/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: gt1x driver
 * Author: lijie
 * Create: 2017-04-02
 */
#include <mem_ops.h>
#include "sre_sys.h"
#include "sre_log.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"

/* Register define */
#define GTP_READ_COOR_ADDR 0x814E
#define GTP_REG_RQST 0x8044

#define GT1X_ADDR_POINT_NUM 0
#define GT1X_LARGE_TOUCH_MASK 0x40
#define GT1X_POINT_DATA_SIZE 8
#define GT1X_X_L_POS 1
#define GT1X_X_H_POS 2
#define GT1X_Y_L_POS 3
#define GT1X_Y_H_POS 4
#define GT1X_PRES_POS 5
#define GT1X_POINT_DATA_OFFSET 1
#define GT1X_BUFF_FIRST_BYTE 1
#define GT1X_BUFF_BYTE_2 2
#define GT1X_SEC_PKG_DATA_START 11
#define GT1X_WRITE_CLEAR_DATA_SIZE 3

extern int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);

enum gt1x_event_id {
    GT1X_EV_DOWN,
    GT1X_EV_UP,
    GT1X_EV_MOVE,
    GT1X_EV_NONE
};

int gt1x_device_init(void)
{
    TP_LOG_ERR("device_init:gt1x \n");
    return 0;
}

int gt1x_get_data(struct ts_tui_fingers *report_data)
{
    int i;
    int ret;
    u8 buf[GT1X_BUFF_FIRST_BYTE + GT1X_POINT_DATA_SIZE *
   TOUCH_MAX_FINGER_NUM + GT1X_BUFF_BYTE_2] = { 0 };
    u8 *coor_data = NULL;
    int touch_num;
    unsigned char input_id;
    struct ts_tui_fingers *info = NULL;
    u8 check_sum = 0;

    if (report_data == NULL)
        return ERROR;

    info = (struct ts_tui_fingers *)malloc(sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return ERROR;
    }

    buf[0] = (GTP_READ_COOR_ADDR >> OFFSET_BYTE8) & 0xFF;
    buf[1] = GTP_READ_COOR_ADDR & 0xFF;
    ret = ts_tui_i2c_read_reg16(buf, (GT1X_BUFF_FIRST_BYTE + GT1X_POINT_DATA_SIZE + GT1X_BUFF_BYTE_2), I2C_GT1X_ADDR);
    if (ret < 0) {
        TP_LOG_ERR("%s:read touchdata failed, ret=%d\n", __func__, ret);
        goto out;
    }

    if (!buf[GT1X_ADDR_POINT_NUM]) {
        TP_LOG_ERR("%s Error touch event!\n", __func__);
        goto out;
    }

    /* get touchNums */
    touch_num = buf[GT1X_ADDR_POINT_NUM] & 0x0F;
    TP_LOG_DEBUG("%s:get touchnum from ic = %d\n", __func__, touch_num);
    if (touch_num > TOUCH_MAX_FINGER_NUM)
        touch_num = TOUCH_MAX_FINGER_NUM;

    if (touch_num > 1) {
        buf[GT1X_SEC_PKG_DATA_START] = ((GTP_READ_COOR_ADDR + GT1X_SEC_PKG_DATA_START) >> OFFSET_BYTE8) & 0xFF;
        buf[GT1X_SEC_PKG_DATA_START + 1] = (GTP_READ_COOR_ADDR + GT1X_SEC_PKG_DATA_START) & 0xFF;
        ret =
            ts_tui_i2c_read_reg16(&buf[GT1X_SEC_PKG_DATA_START], (touch_num - 1) * GT1X_POINT_DATA_SIZE, I2C_GT1X_ADDR);
        if (ret) {
            TP_LOG_ERR("%s:read touchdata failed, ret=%d\n", __func__, ret);
            goto out;
        }
    }

    /* calc checksum */
    for (i = 0; i < GT1X_BUFF_FIRST_BYTE + GT1X_POINT_DATA_SIZE * touch_num + GT1X_BUFF_BYTE_2; i++)
        check_sum += buf[i];

    if (check_sum) {
        TP_LOG_ERR("%s: touchdata checksum calc failed\n", __func__);
        buf[0] = (GTP_READ_COOR_ADDR >> OFFSET_BYTE8) & 0xFF;
        buf[1] = GTP_READ_COOR_ADDR & 0xFF;
        ret = ts_tui_i2c_read_reg16(buf, (GT1X_BUFF_FIRST_BYTE + touch_num * GT1X_POINT_DATA_SIZE + GT1X_BUFF_BYTE_2),
            I2C_GT1X_ADDR);
        if (ret < 0) {
            TP_LOG_ERR("%s:read touchdata failed, ret=%d\n", __func__, ret);
            goto out;
        }
    }

    if (buf[0] & GT1X_LARGE_TOUCH_MASK)
        TP_LOG_ERR("%s: Large touch\n", __func__);

    coor_data = &buf[1];

    for (i = 0; i < touch_num; i++) {
        input_id = coor_data[i * GT1X_POINT_DATA_SIZE] & 0x7F;
        if (input_id >= TOUCH_MAX_FINGER_NUM) {
            TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
            continue;
        }
        info->fingers[input_id].x = ((s16)coor_data[i * GT1X_POINT_DATA_SIZE + GT1X_X_H_POS] << OFFSET_BYTE8) |
            coor_data[i * GT1X_POINT_DATA_SIZE + GT1X_X_L_POS];
        info->fingers[input_id].y = ((s16)coor_data[i * GT1X_POINT_DATA_SIZE + GT1X_Y_H_POS] << OFFSET_BYTE8) |
            coor_data[i * GT1X_POINT_DATA_SIZE + GT1X_Y_L_POS];

        info->fingers[input_id].pressure = buf[i * GT1X_POINT_DATA_SIZE + GT1X_PRES_POS];
        info->fingers[input_id].major = 0;
        info->fingers[input_id].minor = 0;
    }

    /* if touch num ==0; all pointer up */
    info->cur_finger_number = touch_num;
    if (!touch_num) {
        TP_LOG_DEBUG("touchnum = 0, change all pointer to up\n");
        for (input_id = 0; input_id < TOUCH_MAX_FINGER_NUM; input_id++) {
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            info->fingers[input_id].pressure = 0;
        }
    }
    /* clean irq flag */
    buf[0] = (GTP_READ_COOR_ADDR >> OFFSET_BYTE8) & 0xFF;
    buf[OFFSET_BYTE1] = GTP_READ_COOR_ADDR & 0xFF;
    buf[OFFSET_BYTE2] = 0x00;
    ret = ts_tui_i2c_write(buf, GT1X_WRITE_CLEAR_DATA_SIZE, I2C_GT1X_ADDR);
    if (ret < 0)
        TP_LOG_ERR("gt1x write error\n");

    ts_tui_algo_t1(info, report_data);

out:
    free(info);
    return ret;
}
