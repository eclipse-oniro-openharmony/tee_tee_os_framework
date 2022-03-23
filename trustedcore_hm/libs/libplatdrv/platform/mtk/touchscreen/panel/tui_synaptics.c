/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: synaptics tp driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */

#include "tui_touchscreen_panel.h"
#include "tui_touchscreen_platform.h"

#define THP_MAX_FRAME_SIZE (8 * 1024 + 16)
#define SYNA_FRAME_SIZE_MAX 2256
#define SYNA_FRAME_STATUS_ERROR 0xFF
#define MESSAGE_MARKER 0xa5

#define DATA_LEN 4
#define FRAME_LENGTH 1080 /* (2*18*30) */


static struct tee_thp_frame_buff *g_syna_frame_buff = NULL;
static uint8_t *syna_spi_tx_buff = NULL;
static uint8_t *syna_spi_rx_buff = NULL;


enum status_code {
    STATUS_IDLE = 0x00,
    STATUS_OK = 0x01,
    STATUS_BUSY = 0x02,
    STATUS_CONTINUED_READ = 0x03,
    STATUS_RECEIVE_BUFFER_OVERFLOW = 0x0c,
    STATUS_PREVIOUS_COMMAND_PENDING = 0x0d,
    STATUS_NOT_IMPLEMENTED = 0x0e,
    STATUS_ERROR = 0x0f,
    STATUS_INVALID = 0xff,
};

static bool syna_alloc_spi_buff(int size)
{
    if ((size <= 0) || (size > MAX_FRAME_LEN)) {
        tloge("input size is invalid\n");
        return false;
    }

    syna_spi_tx_buff = malloc(size);
    if (syna_spi_tx_buff == NULL) {
        tloge("tx_buff malloc failed\n");
        return false;
    }
    (void)memset_s(syna_spi_tx_buff, size, 0, size);

    syna_spi_rx_buff = malloc(size);
    if (syna_spi_rx_buff == NULL) {
        tloge("rx_buff malloc failed\n");
        free(syna_spi_tx_buff);
        syna_spi_tx_buff = NULL;
        return false;
    }
    (void)memset_s(syna_spi_rx_buff, size, 0, size);
    tloge("%s: succeed\n", __func__);
    return true;
}

static void syna_free_spi_buff(void)
{
    if (syna_spi_tx_buff != NULL) {
        tloge("tx_buff  free\n");
        free(syna_spi_tx_buff);
        syna_spi_tx_buff = NULL;
    }
    if (syna_spi_rx_buff != NULL) {
        tloge("rx_buff  free\n");
        free(syna_spi_rx_buff);
        syna_spi_rx_buff = NULL;
    }
}

int32_t ts_syna_init(void)
{
    bool ret = false;

    tlogi("%s: enter\n", __func__);
    ret = syna_alloc_spi_buff(MAX_FRAME_LEN);
    if (!ret) {
        tloge("%s: error\n", __func__);
        return ERROR;
    }
    tlogi("%s: out\n", __func__);
    return 0;
}

void ts_syna_exit(void)
{
    tlogi("%s: enter\n", __func__);
    syna_free_spi_buff();
}

int32_t ts_syna_get_frame(struct ts_tui_fingers *report_data)
{
    const uint32_t length = SYNA_FRAME_SIZE_MAX;
    int32_t retval;

    tlogd("%s:enter\n", __func__);
    (void)report_data;
    if (g_syna_frame_buff == NULL)
        g_syna_frame_buff = get_tp_frame_buff();

    if ((syna_spi_tx_buff == NULL) || (syna_spi_rx_buff == NULL) ||
        (g_syna_frame_buff == NULL)) {
        tloge("%s:buff is null\n", __func__);
        return ERROR;
    }
    (void)memset_s(syna_spi_tx_buff, length, 0xff, length);
    (void)memset_s(syna_spi_rx_buff, length, 0, length);
    retval = ts_spi_sync(SYNA_FRAME_SIZE_MAX, syna_spi_tx_buff, syna_spi_rx_buff); /* read packet */
    if (retval < 0) {
        tloge("%s: Failed to read data\n", __func__);
        goto error;
    }

    tlogd("%s: 0x%x,  0x%x,  0x%x,  0x%x\n", __func__,
        syna_spi_rx_buff[0], syna_spi_rx_buff[1], syna_spi_rx_buff[2], syna_spi_rx_buff[3]);
    tlogd("%s: 0x%x,  0x%x,  0x%x, 0x%x\n", __func__,
        syna_spi_rx_buff[4], syna_spi_rx_buff[5], syna_spi_rx_buff[6], syna_spi_rx_buff[7]);

    if (syna_spi_rx_buff[1] == SYNA_FRAME_STATUS_ERROR) {
        tloge("%s: should ignore this irq\n", __func__);
        retval = -1;
        goto error;
    }
    if (syna_spi_rx_buff[0] != MESSAGE_MARKER) {
        tloge("%s: incorrect marker: 0x%02x\n", __func__, syna_spi_rx_buff[0]);
        if (syna_spi_rx_buff[1] == STATUS_CONTINUED_READ) {
            /* just in case */
            tloge("%s: continued Read\n", __func__);
            (void)memset_s(syna_spi_tx_buff, length, 0xff, length);
            ts_spi_sync(length, syna_spi_tx_buff, syna_spi_rx_buff); /* drop one transaction */
        }
        retval = -1;
        goto error;
    }
    retval = memcpy_s(g_syna_frame_buff->revbuff, MAX_FRAME_LEN, syna_spi_rx_buff, length);
    if (retval != 0)
        tloge("%s:memcpy_s faied\n", __func__);
    return 0;
error:
    return retval;
}
