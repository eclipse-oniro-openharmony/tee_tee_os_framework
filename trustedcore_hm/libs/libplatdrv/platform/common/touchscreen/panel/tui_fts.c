/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: fts driver
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
#include "../../../kirin/spi/spi.h"
#include "hisi_tui_touchscreen.h"

#define FTS_STATUS_OK 0
#define FTS_STATUS_ERR (-1)

#define FTS_POINT_DATA_SIZE 6
#define TOUCH_DATA_START_ADDR 0x00

#define ADDR_X_H_POS (3 - TOUCH_DATA_START_ADDR)
#define ADDR_X_L_POS (4 - TOUCH_DATA_START_ADDR)
#define ADDR_Y_H_POS (5 - TOUCH_DATA_START_ADDR)
#define ADDR_Y_L_POS (6 - TOUCH_DATA_START_ADDR)
#define ADDR_EVENT_POS (3 - TOUCH_DATA_START_ADDR)
#define ADDR_FINGER_ID_POS (5 - TOUCH_DATA_START_ADDR)
#define ADDR_POINT_NUM (2 - TOUCH_DATA_START_ADDR)
#define ADDR_XY_POS (7 - TOUCH_DATA_START_ADDR)
#define ADDR_MISC (8 - TOUCH_DATA_START_ADDR)
#define TOUCH_DATA_PACKAGE 0x3F

#define FTS_TOUCH_DATA_LEN (3 - TOUCH_DATA_START_ADDR + FTS_POINT_DATA_SIZE * TOUCH_MAX_FINGER_NUM)

#define FTS_ADDR_SIZE 1
#define DELAY_AFTER_FIRST_BYTE 10
#define FTS_SPI_MAX_SPEED 10000000
#define COMMOND_READ_DATA 0x3A
#define DUMMY_DATA 2

static int fts_spi_sync(unsigned short tx_size, unsigned short rx_size, unsigned char *txbuf, unsigned char *rxbuf);

enum fts_event_id {
    FTS_EV_DOWN,
    FTS_EV_UP,
    FTS_EV_MOVE,
    FTS_EV_NONE
};

static struct spi_config_chip tp_chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = 1,
    .cs_control = NULL,
}; /*lint*/

static struct spi_device spi_tp = {
    .max_speed_hz = FTS_SPI_MAX_SPEED,
    .mode = SPI_MODE_1,
    .bits_per_word = 8, /* 8 bit */
    .controller_data = &tp_chip_info,
};

int fts_device_init(void)
{
    TP_LOG_ERR("device_init:focal\n");
    return 0;
}

int fts_get_data(struct ts_tui_fingers *report_data)
{
    int i;
    int ret;
    u32 offset;
    u8 buf[FTS_TOUCH_DATA_LEN] = { 0 };
    int touch_num;
    unsigned char input_id;
    unsigned char event_id;
    struct ts_tui_fingers *info = NULL;

    if (report_data == NULL)
        return FTS_STATUS_ERR;

    info = (struct ts_tui_fingers *)malloc(sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return FTS_STATUS_ERR;
    }

    buf[0] = TOUCH_DATA_START_ADDR;
    ret = ts_tui_i2c_read(buf, (FTS_TOUCH_DATA_LEN), I2C_FTS_ADDR);
    if (ret < 0) {
        TP_LOG_ERR("%s:read touchdata failed, ret=%d.\n", __func__, ret);
        goto out;
    }


    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++)
        info->fingers[i].status = 0;
    /* get records num */
    touch_num = buf[ADDR_POINT_NUM] & 0x0F;
    if (touch_num > TOUCH_MAX_FINGER_NUM)
        touch_num = TOUCH_MAX_FINGER_NUM;

    for (i = 0; i < touch_num; i++) {
        offset = FTS_POINT_DATA_SIZE * i;
        /* touch id */
        input_id = buf[ADDR_FINGER_ID_POS + offset] >> OFFSET_BYTE4;
        if (input_id >= TOUCH_MAX_FINGER_NUM) {
            TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
            continue;
        }
        event_id = buf[ADDR_EVENT_POS + offset] >> OFFSET_BYTE6;

        info->fingers[input_id].event = event_id;
        switch (event_id) { /* PATCH: Huawei does not use our event, they use x=0 or y=0 as this id lift off event */
        case FTS_EV_UP:
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            break;
        case FTS_EV_NONE:
        case FTS_EV_DOWN:
        case FTS_EV_MOVE:
            info->fingers[input_id].x =
                ((s16)(buf[ADDR_X_H_POS + offset] & 0x0F) << OFFSET_BYTE8) | (s16)(buf[ADDR_X_L_POS + offset]);
            info->fingers[input_id].y =
                ((s16)(buf[ADDR_Y_H_POS + offset] & 0x0F) << OFFSET_BYTE8) | (s16)(buf[ADDR_Y_L_POS + offset]);
            break;
        }

        info->fingers[input_id].pressure = (buf[ADDR_XY_POS + offset]);
        info->fingers[input_id].major = (buf[ADDR_MISC + offset]) >> OFFSET_BYTE4;
        info->fingers[input_id].minor = (buf[ADDR_MISC + offset]) >> OFFSET_BYTE4;
    }

    info->cur_finger_number = touch_num;
    ts_tui_algo_t1(info, report_data);
out:
    free(info);
    return ret;
}

int fts_get_data_spi(struct ts_tui_fingers *report_data)
{
    int i;
    int ret;
    unsigned int offset;
    int touch_num;
    unsigned char input_id;
    unsigned char event_id;
    struct ts_tui_fingers *info = NULL;
    unsigned char buf[FTS_TOUCH_DATA_LEN + 1] = { 0 };

    if (report_data == NULL)
        return FTS_STATUS_ERR;

    info = (struct ts_tui_fingers *)malloc(sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return FTS_STATUS_ERR;
    }

    /* set header */
    buf[0] = (TOUCH_DATA_PACKAGE & 0xFF); /* read command */
    ret = fts_spi_sync(FTS_ADDR_SIZE, FTS_TOUCH_DATA_LEN, &buf[0], &buf[1]);
    if (ret != 0) {
        TP_LOG_ERR("%s ts_spi_sync error\n", __func__);
        goto out;
    }

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++)
        info->fingers[i].status = 0;
    /* get records num */
    touch_num = buf[ADDR_POINT_NUM] & 0x0F;
    if (touch_num > TOUCH_MAX_FINGER_NUM)
        touch_num = TOUCH_MAX_FINGER_NUM;

    for (i = 0; i < touch_num; i++) {
        offset = FTS_POINT_DATA_SIZE * i;
        /* touch id */
        input_id = (buf[ADDR_FINGER_ID_POS + offset]) >> OFFSET_BYTE4;
        if (input_id >= TOUCH_MAX_FINGER_NUM) {
            TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
            continue;
        }
        event_id = buf[ADDR_EVENT_POS + offset] >> OFFSET_BYTE6;

        info->fingers[input_id].event = event_id;
        switch (event_id) { /* PATCH: Huawei does not use our event, they use x=0 or y=0 as this id lift off event */
        case FTS_EV_UP:
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            break;
        case FTS_EV_NONE:
        case FTS_EV_DOWN:
        case FTS_EV_MOVE:
            info->fingers[input_id].x =
                ((s16)(buf[ADDR_X_H_POS + offset] & 0x0F) << OFFSET_BYTE8) | (s16)(buf[ADDR_X_L_POS + offset]);
            info->fingers[input_id].y =
                ((s16)(buf[ADDR_Y_H_POS + offset] & 0x0F) << OFFSET_BYTE8) | (s16)(buf[ADDR_Y_L_POS + offset]);
            break;
        }

        info->fingers[input_id].pressure = (buf[ADDR_XY_POS + offset]);
        info->fingers[input_id].major = (buf[ADDR_MISC + offset]) >> OFFSET_BYTE4;
        info->fingers[input_id].minor = (buf[ADDR_MISC + offset]) >> OFFSET_BYTE4;
    }

    info->cur_finger_number = touch_num;
    ts_tui_algo_t1(info, report_data);
out:
    free(info);
    return ret;
}

static int fts_spi_sync(unsigned short tx_size, unsigned short rx_size, unsigned char *txbuf, unsigned char *rxbuf)
{
    int ret;
    unsigned int tp_spi_bus_addr = (unsigned int)TP_SPI_BUS_ADDR;
    struct spi_transfer t[] = {
   {
    .tx_buf = txbuf,
    .len = tx_size,
    .delay_usecs = DELAY_AFTER_FIRST_BYTE,
    .cs_change = 1,
   },
   {
    .rx_buf = rxbuf,
    .len = rx_size,
    .delay_usecs = 0,
    .cs_change = 1,
   },
  }; /*lint !e785*/

    struct spi_message m = {
        .transfers = t,
        .transfer_num = sizeof(t) / sizeof(t[0]),
        .actual_length = 0,
        .status = 0,
    };

    ret = hisi_spi_init(tp_spi_bus_addr, &spi_tp);
    if (ret != 0) {
        TP_LOG_ERR("%s hisi_spi_init failed\n", __func__);
        return ret;
    }

    ts_spi_cs_set(GPIOMUX_LOW);
    hisi_spi_polling_transfer(tp_spi_bus_addr, &m);
    ts_spi_cs_set(GPIOMUX_HIGH);
    hisi_spi_exit(tp_spi_bus_addr);
    if (m.status != 0)
        return FTS_STATUS_ERR;

    return FTS_STATUS_OK;
}

int fts_spi_sync_thp(unsigned short rx_size, unsigned char *txbuf, unsigned char *rxbuf)
{
    int ret;
    struct spi_transfer xfer[2] = { 0 }; /* 2 xfer item */
    unsigned int tp_spi_bus_addr = (unsigned int)TP_SPI_BUS_ADDR;
    struct spi_message m;

    xfer[0].tx_buf = &txbuf[0];
    xfer[0].rx_buf = &rxbuf[0];
    xfer[0].len = FTS_ADDR_SIZE;
    /* Tui does not support usDelay, minimum unit is 'ms', so use 1ms to replace 30us */
    xfer[0].delay_usecs = 1;
    xfer[0].cs_change = 1;

    m.transfers = xfer;
    m.transfer_num = 1;
    m.actual_length = 0;
    m.status = 0;
    /* rx_size > 1, should transfer 2 packages. */
    if (rx_size > 1) {
        xfer[1].tx_buf = &txbuf[1];
        xfer[1].rx_buf = &rxbuf[1];
        xfer[1].len = rx_size - FTS_ADDR_SIZE;
        xfer[1].delay_usecs = 0;
        xfer[1].cs_change = 1;
        m.transfer_num = 2; /* transfer 2 packages */
    }
    ret = hisi_spi_init(tp_spi_bus_addr, &spi_tp);
    if (ret != FTS_STATUS_OK) {
        TP_LOG_ERR("%s hisi_spi_init failed\n", __func__);
        return ret;
    }

    ts_spi_cs_set(GPIOMUX_LOW);
    ret = hisi_spi_polling_transfer(tp_spi_bus_addr, &m);
    ts_spi_cs_set(GPIOMUX_HIGH);
    hisi_spi_exit(tp_spi_bus_addr);

    if (m.status != FTS_STATUS_OK)
        return FTS_STATUS_ERR;

    return ret;
}

int ts_fts_get_frame(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char tx_buff[MAX_FRAME_LEN + DUMMY_DATA] = {0};
    unsigned char rx_buff[MAX_FRAME_LEN + DUMMY_DATA] = {0};

    (void)report_data;
    tx_buff[0] = COMMOND_READ_DATA;

    ret = fts_spi_sync_thp(g_frame_max_len + DUMMY_DATA, &tx_buff[0], &rx_buff[0]);
    if (ret != FTS_STATUS_OK) {
        TP_LOG_ERR("ts_fts_get_frame ts_spi_sync error!\n");
        return FTS_STATUS_ERR;
    }
    (void)memcpy_s((void *)(&g_tee_tp_buff.revbuff[0]), (g_frame_max_len + DUMMY_DATA), (void *)&rx_buff[1],
        (g_frame_max_len + DUMMY_DATA));

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}
