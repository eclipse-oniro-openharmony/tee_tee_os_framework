/*
 * ssl thp tui driver
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ssl thp tui driver
 * Author: weizhenggui
 * Create: 2018-12-24
 */
#include <mem_ops.h>
#include "sre_sys.h"
#include "mem_page_ops.h"
#include "libhwsecurec/securec.h"
#include "tui_panel.h"
#include <platform_touchscreen.h>

struct tee_thp_frame_buff __attribute__((weak)) g_tee_tp_buff;
struct mxt_tui_data __attribute__((weak)) tui_mxt_data;

#define SPI_READ_REQ 0x02
#define SHIFT_BIT_8 8
#define DUMMY_BYTE 400
#define SPI_APP_HEADER_LEN 6
#define SPI_READ_OK 0x82
#define SSL_FRAME_SIZE 1505
#define CRC_INTER_CHECK 0x8c
#define HEADER_LEN_NUM 2

int ts_ssl_init(void)
{
    TP_LOG_INFO("%s !ts ssl address=%d\n", __func__, tui_mxt_data.t5_address);
    return 0;
}

static u8 get_crc8_iter(u8 crc, u8 data)
{
    static const u8 crc_inter_check = CRC_INTER_CHECK;
    u8 index = 8;
    u8 fb;

    do {
        fb = (crc ^ data) & MASK_1BIT;
        data >>= 1;
        crc >>= 1;
        if (fb)
            crc ^= crc_inter_check;
    } while (--index);
    return crc;
}

static u8 get_header_crc(u8 *p_msg)
{
    u8 calc_crc = 0;
    int i;

    if (p_msg == NULL) {
        TP_LOG_ERR("%s: point null\n", __func__);
        return -EINVAL;
    }
    for (i = 0; i < SPI_APP_HEADER_LEN - 1; i++)
        calc_crc = get_crc8_iter(calc_crc, p_msg[i]);
    return calc_crc;
}

static void spi_prepare_header(u8 *header, u8 opcode, u16 start_register, u16 count)
{
    if (header == NULL) {
        TP_LOG_ERR("%s: point null\n", __func__);
        return;
    }

    header[0] = opcode;
    header[OFFSET_BYTE1] = start_register & MASK_8BIT;
    header[OFFSET_BYTE2] = start_register >> SHIFT_BIT_8;
    header[OFFSET_BYTE3] = count & MASK_8BIT;
    header[OFFSET_BYTE4] = count >> SHIFT_BIT_8;
    header[OFFSET_BYTE5] = get_header_crc(header);
}

int ts_ssl_get_frame(struct ts_tui_fingers *report_data)
{
    int ret;
    int dummy_offset = 0;
    int i;
    unsigned char *rx_buf = NULL;
    unsigned char *tx_buf = NULL;

    (void)report_data;
    tx_buf = (unsigned char *)malloc(SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM);
    if (tx_buf == NULL) {
        TP_LOG_ERR("%s: get tx_bufout of memory\n", __func__);
        return -EINVAL;
    }
    rx_buf = (unsigned char *)malloc(SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM);
    if (rx_buf == NULL) {
        TP_LOG_ERR("%s: get rx_buf out of memory\n", __func__);
        free(tx_buf);
        return -EINVAL;
    }

    do {
        ret = memset_s(tx_buf, SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM, 0xFF,
            SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM);
        if (ret) {
            TP_LOG_ERR("%s memset_s error: ret=%d\n", __func__, ret);
            goto data_err;
        }
        ret = memset_s(rx_buf, SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM, 0xFF,
            SSL_FRAME_SIZE + DUMMY_BYTE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM);
        if (ret) {
            TP_LOG_ERR("%s memset_s error: ret=%d\n", __func__, ret);
            goto data_err;
        }
        spi_prepare_header(tx_buf, SPI_READ_REQ, tui_mxt_data.t5_address, SSL_FRAME_SIZE);

        ret = ts_spi_sync(SSL_FRAME_SIZE + SPI_APP_HEADER_LEN * HEADER_LEN_NUM + DUMMY_BYTE, tx_buf, rx_buf);
        if (ret) {
            TP_LOG_ERR("ssl get frame fail ret=%d\n", ret);
            goto data_err;
        }

        for (i = 0; i < DUMMY_BYTE; i++) {
            if (rx_buf[SPI_APP_HEADER_LEN + i] == SPI_READ_OK) {
                dummy_offset = i + SPI_APP_HEADER_LEN;
                if (dummy_offset > (DUMMY_BYTE / HEADER_LEN_NUM))
                    TP_LOG_INFO("Found read dummy offset %d\n", dummy_offset);
                break;
            }
        }
        if (dummy_offset == 0) {
            TP_LOG_ERR("cannot find dummy byte offset- read address =%d\n", tui_mxt_data.t5_address);
            goto data_err;
        } else { /* check tx_buf */
            if ((tx_buf[OFFSET_BYTE1] != rx_buf[OFFSET_BYTE1 + dummy_offset]) ||
                (tx_buf[OFFSET_BYTE2] != rx_buf[OFFSET_BYTE2 + dummy_offset])) {
                TP_LOG_ERR("Unexpected address %d != %d reading from spi\n",
                    rx_buf[OFFSET_BYTE1 + dummy_offset] | (rx_buf[OFFSET_BYTE2 + dummy_offset] << OFFSET_BYTE8),
                    tui_mxt_data.t5_address);
                goto data_err;
            } else if ((tx_buf[OFFSET_BYTE3] != rx_buf[OFFSET_BYTE3 + dummy_offset]) ||
                (tx_buf[OFFSET_BYTE4] != rx_buf[OFFSET_BYTE4 + dummy_offset])) {
                TP_LOG_ERR(" Unexpected count %d != %d reading from spi\n",
                    rx_buf[OFFSET_BYTE3 + dummy_offset] | (rx_buf[OFFSET_BYTE4 + dummy_offset] << OFFSET_BYTE8),
                    SSL_FRAME_SIZE);
                goto data_err;
            }
        }
    } while ((dummy_offset == 0) ||
        (get_header_crc(rx_buf + dummy_offset) != rx_buf[SPI_APP_HEADER_LEN - 1 + dummy_offset]));

    ret =
        memcpy_s(&g_tee_tp_buff.revbuff[0], MAX_FRAME_LEN, rx_buf + SPI_APP_HEADER_LEN + dummy_offset, SSL_FRAME_SIZE);
    if (ret) {
        TP_LOG_ERR("%s memcpy_s error!\n", __func__);
        goto data_err;
    }
    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    free(tx_buf);
    free(rx_buf);
    return NO_ERR;

data_err:
    free(tx_buf);
    free(rx_buf);
    return -EINVAL;
}
