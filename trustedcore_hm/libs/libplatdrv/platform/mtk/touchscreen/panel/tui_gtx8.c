/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: goodix tp driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */
#include "tui_touchscreen_panel.h"
#include "tui_touchscreen_platform.h"

#define GOODIX_FRAME_LEN_MAX_GT9897 2500
#define GOODIX_FRAME_ADDR_GT9897 0x10268
#define REG_READ_CMD_HEAD 0xF1
#define GOODIX_READ_WRITE_BYTE_OFFSET_GT9897 9

#define DUMMY_DATA 3
#define CMD_HEAD_LEN 1
#define DELAY_BYTE 0xFF

static struct tee_thp_frame_buff *g_goodix_frame_buff = NULL;
static uint8_t *goodix_spi_tx_buff = NULL;
static uint8_t *gooidx_spi_rx_buff = NULL;

static bool goodix_alloc_spi_buff(int size)
{
    if ((size <= 0) || (size > MAX_FRAME_LEN)) {
        tloge("input size is invalid\n");
        return false;
    }

    goodix_spi_tx_buff = malloc(size);
    if (goodix_spi_tx_buff == NULL) {
        tloge("tx_buff malloc failed\n");
        return false;
    }
    (void)memset_s(goodix_spi_tx_buff, size, 0, size);

    gooidx_spi_rx_buff = malloc(size);
    if (gooidx_spi_rx_buff == NULL) {
        tloge("rx_buff malloc failed\n");
        free(goodix_spi_tx_buff);
        goodix_spi_tx_buff = NULL;
        return false;
    }
    (void)memset_s(gooidx_spi_rx_buff, size, 0, size);
    return true;
}

static void goodix_free_spi_buff(void)
{
    if (goodix_spi_tx_buff != NULL) {
        free(goodix_spi_tx_buff);
        goodix_spi_tx_buff = NULL;
        tloge("free tx_buff\n");
    }
    if (gooidx_spi_rx_buff != NULL) {
        free(gooidx_spi_rx_buff);
        gooidx_spi_rx_buff = NULL;
        tloge("free rx_buff\n");
    }
}

int32_t ts_goodix_init(void)
{
    bool ret = false;

    tloge("%s: enter\n", __func__);
    ret = goodix_alloc_spi_buff(MAX_FRAME_LEN);
    if (!ret) {
        tloge("%s: error\n", __func__);
        return ERROR;
    }
    tloge("%s: out\n", __func__);
    return 0;
}

void ts_goodix_exit(void)
{
    tlogi("%s: enter\n", __func__);
    goodix_free_spi_buff();
}

int ts_goodix_get_frame(struct ts_tui_fingers *report_data)
{
    int ret;

    if (g_goodix_frame_buff == NULL)
        g_goodix_frame_buff = get_tp_frame_buff();

    if ((goodix_spi_tx_buff == NULL) || (gooidx_spi_rx_buff == NULL) ||
        (g_goodix_frame_buff == NULL)) {
        tloge("%s:buff is null\n", __func__);
        return ERROR;
    }
    (void)report_data;
    goodix_spi_tx_buff[0] = REG_READ_CMD_HEAD;
    goodix_spi_tx_buff[1] = (GOODIX_FRAME_ADDR_GT9897 >> 24) & 0xFF;
    goodix_spi_tx_buff[2] = (GOODIX_FRAME_ADDR_GT9897 >> 16) & 0xFF;
    goodix_spi_tx_buff[3] = (GOODIX_FRAME_ADDR_GT9897 >> 8) & 0xFF;
    goodix_spi_tx_buff[4] = GOODIX_FRAME_ADDR_GT9897 & 0xFF;
    goodix_spi_tx_buff[5] = DELAY_BYTE;
    goodix_spi_tx_buff[5] = DELAY_BYTE;
    goodix_spi_tx_buff[6] = DELAY_BYTE;
    goodix_spi_tx_buff[7] = DELAY_BYTE;
    ret = ts_spi_sync(GOODIX_FRAME_LEN_MAX_GT9897 + CMD_HEAD_LEN,
        goodix_spi_tx_buff, gooidx_spi_rx_buff);
    tlogd("%s:0x%x,  0x%x,  0x%x,  0x%x\n", __func__,
       gooidx_spi_rx_buff[0], gooidx_spi_rx_buff[1], gooidx_spi_rx_buff[2], gooidx_spi_rx_buff[3]);
    tlogd("%s:0x%x,  0x%x,  0x%x,  0x%x\n", __func__,
       gooidx_spi_rx_buff[4], gooidx_spi_rx_buff[5], gooidx_spi_rx_buff[6], gooidx_spi_rx_buff[7]);
    if (ret) {
        tloge("%s: ts_spi_sync error, ret = %d\n", __func__, ret);
        return -1;
    }
    /* skip the cmd_head data */
    ret = memcpy_s(&g_goodix_frame_buff->revbuff[0], GOODIX_FRAME_LEN_MAX_GT9897,
        &gooidx_spi_rx_buff[GOODIX_READ_WRITE_BYTE_OFFSET_GT9897], GOODIX_FRAME_LEN_MAX_GT9897);
    if (ret) {
        tloge("%s: memcpy_s error, ret = %d\n", __func__, ret);
        return -1;
    }

    if (g_goodix_frame_buff->flag == false)
        g_goodix_frame_buff->flag = true;
    return 0;
}
