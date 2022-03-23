/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: jdi driver
 * Author: lijie
 * Create: 2017-5-22
 */
#include <mem_ops.h>
#include "sre_sys.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"

#define COMM_TEST_REG 0x009a
#define COMM_TEST_RW_LENGTH 8
#define SPI_HEADER_SIZE 3
#define REG_READ_DATA 0x0400

unsigned char output_buf[MAX_FRAME_LEN + SPI_HEADER_SIZE];
extern int g_frame_max_len;
struct tee_thp_frame_buff __attribute__((weak)) g_tee_tp_buff;
extern void ts_swap_2byte(unsigned char *buf, unsigned int size);

int ts_jdi_init(void)
{
    unsigned char buf_zero[COMM_TEST_RW_LENGTH + SPI_HEADER_SIZE] = {0};
    unsigned char buf_read[COMM_TEST_RW_LENGTH + SPI_HEADER_SIZE] = {0};
    unsigned char buf_org[COMM_TEST_RW_LENGTH + SPI_HEADER_SIZE] = { 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    unsigned char buff[SPI_HEADER_SIZE];

    memset_s((void *)&g_tee_tp_buff, sizeof(g_tee_tp_buff), 0, sizeof(g_tee_tp_buff));

    buf_org[0] = 0x02;                                                /* write command */
    buf_org[OFFSET_BYTE1] = (COMM_TEST_REG & 0xFF00) >> OFFSET_BYTE8; /* address hi */
    buf_org[OFFSET_BYTE2] = (COMM_TEST_REG & 0x00FF) >> 0;            /* address lo */
    ts_spi_sync(COMM_TEST_RW_LENGTH + OFFSET_BYTE3, (unsigned char *)buf_org, NULL);

    buff[0] = 0x03;                                                /* read command */
    buff[OFFSET_BYTE1] = (COMM_TEST_REG & 0xFF00) >> OFFSET_BYTE8; /* address hi */
    buff[OFFSET_BYTE2] = (COMM_TEST_REG & 0x00FF) >> 0;            /* address lo */
    ts_spi_sync(COMM_TEST_RW_LENGTH + OFFSET_BYTE3, buff, buf_read);

    buf_zero[0] = 0x02;                                                /* write command */
    buf_zero[OFFSET_BYTE1] = (COMM_TEST_REG & 0xFF00) >> OFFSET_BYTE8; /* address hi */
    buf_zero[OFFSET_BYTE2] = (COMM_TEST_REG & 0x00FF) >> 0;            /* address lo */
    ts_spi_sync(COMM_TEST_RW_LENGTH + SPI_HEADER_SIZE, (unsigned char *)buf_zero, NULL);

    if (!strncmp((char *)&buf_read[SPI_HEADER_SIZE], (char *)&buf_org[SPI_HEADER_SIZE],
        (unsigned int)COMM_TEST_RW_LENGTH)) {
        TP_LOG_ERR("spi comm check success\n");
        return 0;
    } else {
        TP_LOG_ERR("spi comm failed\n");
    }
    return ERROR;
}

int ts_jdi_get_frame(struct ts_tui_fingers *report_data)
{
    unsigned char buff[MAX_FRAME_LEN + SPI_HEADER_SIZE];
    unsigned int ret;
    (void)report_data;

    /* set header */
    buff[0] = 0x03;                                                /* read command */
    buff[OFFSET_BYTE1] = (REG_READ_DATA & 0xFF00) >> OFFSET_BYTE8; /* address hi */
    buff[OFFSET_BYTE2] = (REG_READ_DATA & 0x00FF) >> 0;            /* address lo */

    ret = ts_spi_sync((g_frame_max_len + SPI_HEADER_SIZE), &buff[0], output_buf);
    if (ret != 0) {
        TP_LOG_ERR("ts_jdi_get_frame ts_spi_sync error\n");
        return ERROR;
    }

    ret = memcpy_s((void *)&g_tee_tp_buff.revbuff[0], MAX_FRAME_LEN, (void *)&output_buf[SPI_HEADER_SIZE],
        g_frame_max_len);
    if ((g_tee_tp_buff.flag == 0) && (!ret))
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}
