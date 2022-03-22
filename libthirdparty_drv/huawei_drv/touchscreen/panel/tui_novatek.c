/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: novatek driver
 * Author: lijie
 * Create: 2017-5-22
 */
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"

extern int g_frame_max_len;
struct tee_thp_frame_buff __attribute__((weak)) g_tee_tp_buff;
extern int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);

#define NOVA_ERR (-1)
#define NOVA_READ_LENTH 256
#define NOVA_SPI_DUMMY_LEN 2

#define NOVA_FINGER_STATUS_MASK 0x07
#define NOVA_FINGER_UP 0x03

#define W_MAJOR_MAX 255
#define W_MINOR_MAX 255

/* for novatek which use i2c interface */
int novatek_device_init(void)
{
    unsigned char buf[18] = {0}; /* chip communicate buffer 18 = 16+2 */
    unsigned int retry_count = 0;
    char ret = 0;

    TP_LOG_ERR("novatek_device_init:name is novatek\n");
info_retry:
    /* ---set xdata index to 0x11E00--- */
    buf[0] = 0xFF;
    buf[OFFSET_BYTE1] = 0x01;
    buf[OFFSET_BYTE2] = 0x1E;
    ts_tui_i2c_write(buf, 0x3, I2C_NOVA_FW_ADDR);

    /* ---read fw info--- */
    buf[0] = 0x78;
    ts_tui_i2c_read(buf, 0x11, I2C_NOVA_FW_ADDR);
    /* ---clear x_num, y_num if fw info is broken--- */
    if ((buf[0] + buf[1]) != 0xFF) {
        TP_LOG_ERR("%s: FW info is broken! nvt_fw_ver=%d, ~nvt_fw_ver=%d\n", __func__, buf[0], buf[1]);
		/* ---retry 3 times--- */
        if (retry_count < 3) {
            retry_count++;
            TP_LOG_ERR("%s: retry_count=%d\n", __func__, retry_count);
            goto info_retry;
        } else {
            ret = -1;
        }
    } else {
        ret = 0;
    }
    return ret;
}

/* for novatek which use i2c interface */
int novatek_get_data(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char point_data[66] = {0}; /* nova tek point packat len max 66 */
    unsigned int position;
    unsigned int input_x;
    unsigned int input_y;
    unsigned int input_w_major;
    unsigned int input_w_minor;
    unsigned char input_id;
    int i;
    int finger_cnt;
    struct ts_tui_fingers *info = NULL;
    int temp_finger_status = 0; /* not really useful here lijie00175727 */

    if (report_data == NULL)
        return ERROR;

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return ERROR;
    }
    /* 64 is data max len */
    ret = ts_tui_i2c_read(point_data, 64 + 1, I2C_NOVA_FW_ADDR);
    if (ret < 0) {
        TP_LOG_ERR("%s: ts_kit_i2c_read failed. ret=%d\n", __func__, ret);
        goto out;
    }

    finger_cnt = 0;
    input_id = (unsigned char)(point_data[1] >> OFFSET_BYTE3);

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++)
        /*
         * Each 2-bit finger status field represents the following:
         * 00 = finger not present
         * 01 = finger present and data accurate
         * 10 = finger present but data may be inaccurate
         * 11 = reserved
         */
        info->fingers[i].status = 0;

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++) {
        position = 6 * i; /* length is 6 */
        input_id = (unsigned char)(point_data[position + 0] >> OFFSET_BYTE3);
        if (input_id > TOUCH_MAX_FINGER_NUM)
            continue;

        /* finger up (break) */
        if ((point_data[position] & 0x07) == 0x03) {
            continue;
        } else if (((point_data[position] & 0x07) == FINGER_ENTER) ||
            ((point_data[position] & 0x07) == FINGER_MOVING) || ((point_data[position] & 0x07) == GLOVE_TOUCH)) {
            input_x = (unsigned int)(point_data[position + OFFSET_BYTE1] << OFFSET_BYTE4) +
                (unsigned int)(point_data[position + OFFSET_BYTE3] >> OFFSET_BYTE4);
            input_y = (unsigned int)(point_data[position + OFFSET_BYTE2] << OFFSET_BYTE4) +
                (unsigned int)(point_data[position + OFFSET_BYTE3] & 0x0F);
            input_w_major = (unsigned int)(point_data[position + OFFSET_BYTE4]);
            if (input_w_major > 0xFF)
                input_w_major = 0xFF;
            input_w_minor = (unsigned int)(point_data[position + OFFSET_BYTE5]);
            if (input_w_minor > 0xFF)
                input_w_minor = 0xFF;

            info->fingers[input_id - 1].status =
                ((point_data[position] & 0x07) == GLOVE_TOUCH) ? GLOVE_TOUCH : FINGER_ENTER;
            info->fingers[input_id - 1].x = input_x;
            info->fingers[input_id - 1].y = input_y;
            info->fingers[input_id - 1].major = input_w_major;
            info->fingers[input_id - 1].minor = input_w_minor;

            finger_cnt++;
            temp_finger_status++;
        }
    }

    info->cur_finger_number = finger_cnt;
    ts_tui_algo_t1(info, report_data);
out:
    SRE_MemFree(0, info);
    return ret;
}

/* for novatek which use spi interface */
int novatek_device_init_spi(void)
{
    TP_LOG_INFO("%s +++\n", __func__);
    return 0;
}

/* for novatek which use spi interface */
int novatek_get_data_spi(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char point_data[NOVA_READ_LENTH] = {0};
    unsigned int position;
    unsigned int input_x;
    unsigned int input_y;
    unsigned int input_w_major;
    unsigned int input_w_minor;
    unsigned char input_id;
    int i;
    int finger_cnt;
    struct ts_tui_fingers *info = NULL;

    if (report_data == NULL) {
        TP_LOG_ERR("%s: parameter report_data is not valid.\n", __func__);
        return NOVA_ERR;
    }

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return NOVA_ERR;
    }

    ret = ts_spi_sync(NOVA_READ_LENTH, NULL, point_data);
    if (ret < 0) {
        TP_LOG_ERR("%s: ts_kit_spi_read failed. ret=%d\n", __func__, ret);
        goto out;
    }

    finger_cnt = 0;
    input_id = (unsigned char)(point_data[1] >> OFFSET_BYTE3);

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++)
        /*
         * Each 2-bit finger status field represents the following:
         * 00 = finger not present
         * 01 = finger present and data accurate
         * 10 = finger present but data may be inaccurate
         * 11 = reserved
         */
        info->fingers[i].status = 0;

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++) {
        /* we will get 2 bytes dummy data from spi data length is 6 */
        position = NOVA_SPI_DUMMY_LEN + 6 * i;
        input_id = (unsigned char)(point_data[position + 0] >> OFFSET_BYTE3);
        if (input_id > TOUCH_MAX_FINGER_NUM)
            continue;

        if ((point_data[position] & NOVA_FINGER_STATUS_MASK) == NOVA_FINGER_UP) { /* finger up (break) */
            continue;
        } else if (((point_data[position] & NOVA_FINGER_STATUS_MASK) == FINGER_ENTER) ||
            ((point_data[position] & NOVA_FINGER_STATUS_MASK) == FINGER_MOVING) ||
            ((point_data[position] & NOVA_FINGER_STATUS_MASK) == GLOVE_TOUCH)) {
            input_x = (unsigned int)(point_data[position + OFFSET_BYTE1] << OFFSET_BYTE4) +
                (unsigned int)(point_data[position + OFFSET_BYTE3] >> OFFSET_BYTE4);
            input_y = (unsigned int)(point_data[position + OFFSET_BYTE2] << OFFSET_BYTE4) +
                (unsigned int)(point_data[position + OFFSET_BYTE3] & 0x0F);
            input_w_major = (unsigned int)(point_data[position + OFFSET_BYTE4]);
            if (input_w_major > W_MAJOR_MAX)
                input_w_major = W_MAJOR_MAX;
            input_w_minor = (unsigned int)(point_data[position + OFFSET_BYTE5]);
            if (input_w_minor > W_MINOR_MAX)
                input_w_minor = W_MINOR_MAX;

            info->fingers[input_id - 1].status =
                ((point_data[position] & NOVA_FINGER_STATUS_MASK) == GLOVE_TOUCH) ? GLOVE_TOUCH : FINGER_ENTER;
            info->fingers[input_id - 1].x = input_x;
            info->fingers[input_id - 1].y = input_y;
            info->fingers[input_id - 1].major = input_w_major;
            info->fingers[input_id - 1].minor = input_w_minor;

            finger_cnt++;
        }
    }

    info->cur_finger_number = finger_cnt;
    ts_tui_algo_t1(info, report_data);
out:
    SRE_MemFree(0, info);
    return ret;
}

int ts_novatek_init(void)
{
    TP_LOG_ERR("ts_novatek_init\n");
    return 0;
}

int ts_novatek_get_frame(struct ts_tui_fingers *report_data)
{
#define DUMMY_DATA 2
#define REG_GET_FRAME 0x20
    unsigned char buff[MAX_FRAME_LEN + DUMMY_DATA];
    unsigned int ret;
    (void)report_data;

    /* set header */
    buff[0] = (REG_GET_FRAME & 0x7F); /* read command */
    ret = ts_spi_sync(g_frame_max_len + DUMMY_DATA, &buff[0], &g_tee_tp_buff.revbuff[0]);
    if (ret != 0) {
        TP_LOG_ERR("ts_novatek_get_frame ts_spi_sync error\n");
        return ERROR;
    }

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}
