/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: gt1x driver
 * Author: weizhenggui
 * Create: 2018-12-22
 */
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <mem_ops.h>
#include "sre_typedef.h"
#include "sre_sys.h"
#include "sre_log.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"
#include "mem_page_ops.h"
#include "hisi_tui_touchscreen.h"

#define GTX8_DATA_START_ADDR 0x4100
#define GTX8_BYTES_PER_COORD 8
#define GTX8_TP_MAX_TOUCH 10
#define GTX8_BUFF_BYTE_4 4
#define GTX8_WRITE_CLEAR_DATA_SIZE 3
#define GTX8_SEC_PKG_DATA_START 12
#define GTX8_X_L_POS 1
#define GTX8_X_H_POS 2
#define GTX8_Y_L_POS 3
#define GTX8_Y_H_POS 4
#define GTX8_PRES_POS 5
#define GTX8_SHIFT_8 8
#define GTX8_PEN_FLAG 0x80
#define GTX8_BUF_LEN_2 2
#define GTX8_DATA_HEAD 0x00

#define VRD_PANEL_RESOLUTION_X 1600
#define VRD_PANEL_RESOLUTION_Y 2560
#define VRD_TOUCH_FW_RESOLUTION_X 2816
#define VRD_TOUCH_FW_RESOLUTION_Y 5210
#define GTX8_RECALCULATE_RES_TRUE 1
#define GTX8_RECALCULATE_RES_FALSE 0

static int gtx8_recalculate_resolution;


extern struct tee_thp_frame_buff g_tee_tp_buff;

#define DUMMY_DATA 3
#define CMD_HEAD_LEN 1
#define REG_WRITE_CMD_HEAD 0xF0
#define REG_READ_CMD_HEAD 0xF1
#define GOODIX_FRAME_ADDR 0x8C05
#define GOODIX_FRAME_ADDR_GT9896 0x4280
#define GOODIX_FRAME_LEN 1500
#define READ_WRITE_BYTE_OFFSET_GT9896 5
#define MOVE_8BIT 8
#define MOVE_16BIT 16
#define MOVE_24BIT 24
#define GOODIX_FRAME_ADDR_GT9897 0x10268
#define GOODIX_FRAME_LEN_MAX_GT9897 2500
#define GOODIX_READ_WRITE_BYTE_OFFSET_GT9897 9

extern int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);

int gtx8_device_init(void)
{
    int chip_type;

    TP_LOG_INFO("device_init:gtx8 !\n");
    chip_type = hisi_tui_get_chip_type();
    TP_LOG_INFO("chip_type = %d\n", chip_type);
    if (chip_type == GTX8_DEVICE_VRD)
        gtx8_recalculate_resolution = GTX8_RECALCULATE_RES_TRUE;
    else
        gtx8_recalculate_resolution = GTX8_RECALCULATE_RES_FALSE;
    return 0;
}

int gtx8_get_data(struct ts_tui_fingers *report_data)
{
    int ret;
    int i;
    int have_pen;
    u8 *coor_data = NULL;
    unsigned char input_id = 0;
    int touch_num;
    u8 checksum = 0;
    u8 buf[GTX8_BYTES_PER_COORD * GTX8_TP_MAX_TOUCH + GTX8_BUFF_BYTE_4];
    unsigned int x;
    unsigned int y;
    struct ts_tui_fingers *info = NULL;

    if (report_data == NULL) {
        TP_LOG_ERR("%s: report_data NULL!\n", __func__);
        return -EINVAL;
    }

    TP_LOG_DEBUG("gtx8_get_data IN !\n");
    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return -EINVAL;
    }

    buf[0] = (u8)((GTX8_DATA_START_ADDR >> GTX8_SHIFT_8) & 0xFF);
    buf[1] = (u8)(GTX8_DATA_START_ADDR & 0xFF);
    ret = ts_tui_i2c_read_reg16(buf, (GTX8_BYTES_PER_COORD + GTX8_BUFF_BYTE_4), I2C_GTX8_ADDR);
    if (ret < 0) {
        TP_LOG_ERR("%s:read touchdata failed, ret=%d.\n", __func__, ret);
        goto out;
    }

    touch_num = buf[1] & 0x0F;
    if ((touch_num > TOUCH_MAX_FINGER_NUM)) {
        TP_LOG_ERR("touch_num error: num= %d", touch_num);
        ret = -EINVAL;
        goto out;
    }
    /* read the rest data */
    if (touch_num > 1) {
        buf[GTX8_SEC_PKG_DATA_START] =
            (u8)(((GTX8_DATA_START_ADDR + GTX8_SEC_PKG_DATA_START) >> GTX8_SHIFT_8) & MASK_8BIT);
        buf[GTX8_SEC_PKG_DATA_START + 1] = (u8)((GTX8_DATA_START_ADDR + GTX8_SEC_PKG_DATA_START) & MASK_8BIT);
        ret = ts_tui_i2c_read_reg16(&buf[GTX8_BYTES_PER_COORD + GTX8_BUFF_BYTE_4],
            (touch_num - 1) * GTX8_BYTES_PER_COORD, I2C_GTX8_ADDR);
        if (ret < 0) {
            TP_LOG_ERR("%s:read touchdata failed, ret=%d.\n", __func__, ret);
            goto out;
        }
    }
    /* calculate checksum */
    for (i = 0; i < GTX8_BYTES_PER_COORD * touch_num + GTX8_BUFF_BYTE_4; i++)
        checksum += buf[i];

    if (checksum != 0) {
        ret = -EINVAL;
        goto out;
    }
    /* if there is a pen, it's must be the last touch data; if trace id >= 0x80, it's a pen */
    if (touch_num >= 1 && buf[GTX8_BYTES_PER_COORD * (touch_num - 1) + GTX8_BUF_LEN_2] >= GTX8_PEN_FLAG) {
        have_pen = 1;
    } else {
        have_pen = 0;
    }

    if (have_pen) {
        /* pen report */
        coor_data = &buf[GTX8_BYTES_PER_COORD * (touch_num - 1) + GTX8_BUF_LEN_2];
        if (coor_data[GTX8_PRES_POS] == 0) {
            touch_num = 0;
            goto point_up;
        } else {
            info->fingers[input_id].x = coor_data[GTX8_X_L_POS] | (coor_data[GTX8_X_H_POS] << GTX8_SHIFT_8);
            info->fingers[input_id].y = coor_data[GTX8_Y_L_POS] | (coor_data[GTX8_Y_H_POS] << GTX8_SHIFT_8);
            info->fingers[input_id].pressure = coor_data[GTX8_PRES_POS];
            TP_LOG_DEBUG("gtx8 P:[%d] , w %d.\n", input_id, info->fingers[input_id].pressure);
        }
    } else {
        /* finger report */
        coor_data = &buf[GTX8_BUF_LEN_2];

        for (i = 0; i < touch_num; i++) {
            input_id = coor_data[i * GTX8_BYTES_PER_COORD];
            if (input_id >= TOUCH_MAX_FINGER_NUM) {
                TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
                break;
            }

            x = coor_data[i * GTX8_BYTES_PER_COORD + GTX8_X_L_POS] |
                (coor_data[i * GTX8_BYTES_PER_COORD + GTX8_X_H_POS] << GTX8_SHIFT_8);
            y = coor_data[i * GTX8_BYTES_PER_COORD + GTX8_Y_L_POS] |
                (coor_data[i * GTX8_BYTES_PER_COORD + GTX8_Y_H_POS] << GTX8_SHIFT_8);
            if (gtx8_recalculate_resolution) {
                info->fingers[input_id].x = x * VRD_PANEL_RESOLUTION_X / VRD_TOUCH_FW_RESOLUTION_X;
                info->fingers[input_id].y = y * VRD_PANEL_RESOLUTION_Y / VRD_TOUCH_FW_RESOLUTION_Y;
            } else {
                info->fingers[input_id].x = x;
                info->fingers[input_id].y = y;
            }
            info->fingers[input_id].pressure = coor_data[i * GTX8_BYTES_PER_COORD + GTX8_PRES_POS];
            info->fingers[input_id].major = 0;
            info->fingers[input_id].minor = 0;

            TP_LOG_DEBUG("gtx8 F:[%d], w %d.\n", input_id, info->fingers[input_id].pressure);
        }
    }

    /* if touch num ==0; all pointer up */
point_up:
    info->cur_finger_number = touch_num;
    if (!touch_num) {
        TP_LOG_DEBUG("touchnum = 0, change all pointer to up. \n");
        for (input_id = 0; input_id < TOUCH_MAX_FINGER_NUM; input_id++) {
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            info->fingers[input_id].pressure = 0;
        }
    }

    /* clean irq flag */
    buf[0] = (GTX8_DATA_START_ADDR >> GTX8_SHIFT_8) & MASK_8BIT;
    buf[OFFSET_BYTE1] = GTX8_DATA_START_ADDR & MASK_8BIT;
    buf[OFFSET_BYTE2] = GTX8_DATA_HEAD;
    ret = ts_tui_i2c_write(buf, GTX8_WRITE_CLEAR_DATA_SIZE, I2C_GTX8_ADDR);
    if (ret < 0)
        TP_LOG_ERR("ts_tui_i2c_write error\n");

    TP_LOG_DEBUG("gtx8 info!:[%d], w %d.\n", input_id, info->fingers[input_id].pressure);

    ts_tui_algo_t1(info, report_data);

out:
    SRE_MemFree(0, info);
    return ret;
}

int ts_goodix_init(void)
{
    TP_LOG_INFO("ts_goodix_init\n");
    return NO_ERR;
}

int ts_goodix_get_frame_gt9897(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char buff_temp[GOODIX_FRAME_LEN_MAX_GT9897 + DUMMY_DATA] = {0};
    unsigned char buff_data[GOODIX_FRAME_LEN_MAX_GT9897 + DUMMY_DATA] = {0};

    (void)report_data;
    buff_temp[0] = REG_READ_CMD_HEAD;
    buff_temp[OFFSET_BYTE1] = (GOODIX_FRAME_ADDR_GT9897 >> MOVE_24BIT) & MASK_8BIT;
    buff_temp[OFFSET_BYTE2] = (GOODIX_FRAME_ADDR_GT9897 >> MOVE_16BIT) & MASK_8BIT;
    buff_temp[OFFSET_BYTE3] = (GOODIX_FRAME_ADDR_GT9897 >> MOVE_8BIT) & MASK_8BIT;
    buff_temp[OFFSET_BYTE4] = GOODIX_FRAME_ADDR_GT9897 & MASK_8BIT;
    buff_temp[OFFSET_BYTE5] = MASK_8BIT;
    buff_temp[OFFSET_BYTE6] = MASK_8BIT;
    buff_temp[OFFSET_BYTE7] = MASK_8BIT;
    buff_temp[OFFSET_BYTE8] = MASK_8BIT;
    ret = ts_spi_sync(GOODIX_FRAME_LEN_MAX_GT9897 + CMD_HEAD_LEN, &buff_temp[0], &buff_data[0]);
    if (ret) {
        TP_LOG_ERR("%s: ts_spi_sync error\n", __func__);
        return -EINVAL;
    }
    /* skip the cmd_head data */
    ret = memcpy_s(&g_tee_tp_buff.revbuff[0], GOODIX_FRAME_LEN_MAX_GT9897, &buff_data[GOODIX_READ_WRITE_BYTE_OFFSET_GT9897],
        GOODIX_FRAME_LEN_MAX_GT9897);
    if (ret) {
        TP_LOG_ERR("%s: memcpy_s error, ret = %d\n", __func__, ret);
        return -EINVAL;
    }

    if (g_tee_tp_buff.flag == false)
        g_tee_tp_buff.flag = true;

    return NO_ERR;
}

int ts_goodix_get_frame_gt9896(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char buff_temp[GOODIX_FRAME_LEN + DUMMY_DATA] = {0};
    unsigned char buff_data[GOODIX_FRAME_LEN + DUMMY_DATA] = {0};

    (void)report_data;
    /* buf0~buf4 is: start read flag, addr high 8bit, addr low 8bit, Protocol
     * specification, Protocol specification
     */
    buff_temp[0] = REG_READ_CMD_HEAD;
    buff_temp[OFFSET_BYTE1] = (GOODIX_FRAME_ADDR_GT9896 >> OFFSET_BYTE8) & MASK_8BIT;
    buff_temp[OFFSET_BYTE2] = GOODIX_FRAME_ADDR_GT9896 & MASK_8BIT;
    buff_temp[OFFSET_BYTE3] = MASK_8BIT;
    buff_temp[OFFSET_BYTE4] = MASK_8BIT;

    ret = ts_spi_sync(GOODIX_FRAME_LEN + CMD_HEAD_LEN, &buff_temp[0], &buff_data[0]);
    if (ret) {
        TP_LOG_ERR("%s: ts_spi_sync error\n", __func__);
        return -EINVAL;
    }
    /* skip the cmd_head data */
    ret = memcpy_s(&g_tee_tp_buff.revbuff[0], GOODIX_FRAME_LEN, &buff_data[READ_WRITE_BYTE_OFFSET_GT9896],
        GOODIX_FRAME_LEN);
    if (ret) {
        TP_LOG_ERR("%s: memcpy_s error, ret = %d\n", __func__, ret);
        return -EINVAL;
    }

    if (g_tee_tp_buff.flag == false)
        g_tee_tp_buff.flag = true;

    return NO_ERR;
}

int ts_goodix_get_frame(struct ts_tui_fingers *report_data)
{
    int ret;
    unsigned char buff_temp[GOODIX_FRAME_LEN + DUMMY_DATA] = {0};
    unsigned char buff_data[GOODIX_FRAME_LEN + DUMMY_DATA] = {0};

    (void)report_data;
    buff_temp[0] = REG_WRITE_CMD_HEAD;
    buff_temp[OFFSET_BYTE1] = (GOODIX_FRAME_ADDR >> OFFSET_BYTE8) & MASK_8BIT;
    buff_temp[OFFSET_BYTE2] = GOODIX_FRAME_ADDR & MASK_8BIT;

    ret = ts_spi_sync(DUMMY_DATA, &buff_temp[0], &g_tee_tp_buff.revbuff[0]);
    if (ret) {
        TP_LOG_ERR("ts_goodix_get_frame write F0 error\n");
        return -EINVAL;
    }

    buff_temp[0] = REG_READ_CMD_HEAD;
    ret = ts_spi_sync(GOODIX_FRAME_LEN + CMD_HEAD_LEN, &buff_temp[0], &buff_data[0]);
    if (ret) {
        TP_LOG_ERR("ts_goodix_get_frame ts_spi_sync error\n");
        return -EINVAL;
    }
    /* skip the cmd_head data */
    ret = memcpy_s(&g_tee_tp_buff.revbuff[0], GOODIX_FRAME_LEN, &buff_data[1], GOODIX_FRAME_LEN);
    if (ret) {
        TP_LOG_ERR("ts_goodix_get_frame memcpy_s error\n");
        return -EINVAL;
    }

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}

#define BRL_I3C_ADDR 0x5d
#define BRL_TRANSFER_MAX_SIZE 4096
#define BRL_MAX_TOUCH 10
#define BRL_WRITE_BUF_LEN_MAX 20
#define BRL_WRITE_ADDR_OFFSET 4
static int brl_i3c_read_data(unsigned char *data,
    unsigned int length)
{
    int retval;

    retval = ts_tui_i3c_block_read(data, length, BRL_I3C_ADDR, 4); /* 4:bus num */
    return retval;
}

static int brl_i3c_write_data(unsigned char *data,
    unsigned int length)
{
    int retval;

    retval = ts_tui_i3c_block_write(data, length, BRL_I3C_ADDR, 4); /* 4:bus num */
    return retval;
}

static int brl_i3c_read_transfer(u32 addr, u8 *buffer, u32 len)
{
    u8 data[4] = {0};
    int ret;

    /* split the u32 data into four u8 data */
    data[0] = (u8)((addr >> 24) & 0xFF); /* 24:move 24 bit */
    data[1] = (u8)((addr >> 16) & 0xFF); /* 16:move 16 bit */
    data[2] = (u8)((addr >> 8) & 0xFF); /* 2:data offset 8:move 8 bit */
    data[3] = (u8)(addr & 0xFF); /* 3:data offset */
    ret = brl_i3c_write_data(data, sizeof(data));
    if (ret < 0)
        TP_LOG_ERR("%s:i3c write error,addr:%04x bytes:%u\n",
            __func__, addr, len);
    ret = brl_i3c_read_data(buffer, len);
    if (ret < 0)
        TP_LOG_ERR("%s:i3c read error,addr:%04x bytes:%u\n",
            __func__, addr, len);
    return ret;
}

static int brl_i3c_write_transfer(u32 addr, u8 *buffer, u32 len)
{
    u8 data[BRL_WRITE_BUF_LEN_MAX] = {0};
    int ret;

    if (len > BRL_WRITE_BUF_LEN_MAX - BRL_WRITE_ADDR_OFFSET) {
        TP_LOG_ERR("%s:i2c write error len over max\n", __func__);
        return -EINVAL;
    }
    data[0] = (u8)((addr >> 24) & 0xFF);
    data[1] = (u8)((addr >> 16) & 0xFF);
    data[2] = (u8)((addr >> 8) & 0xFF);
    data[3] = (u8)(addr & 0xFF);
    ret = memcpy_s(&data[BRL_WRITE_ADDR_OFFSET], (BRL_WRITE_BUF_LEN_MAX - BRL_WRITE_ADDR_OFFSET),
        buffer, len);
    if (ret) {
        TP_LOG_ERR("%s:i3c write transter memcpy failed\n",
            __func__, addr, len);
        return -EINVAL;
    }
    ret = brl_i3c_write_data(data, len + BRL_WRITE_ADDR_OFFSET);
    if (ret < 0)
        TP_LOG_ERR("%s:i2c write error,addr:%04x bytes:%d\n",
            __func__, addr, len);
    return ret;
}

int brl_i3c_read(u32 addr, u8 *buffer, u32 len)
{
    int col;
    int remain;
    int i;
    int ret = -EINVAL;
    u32 temp_addr;
    u8 *temp_buf = NULL;

    col = len / BRL_TRANSFER_MAX_SIZE;
    remain = len % BRL_TRANSFER_MAX_SIZE;
    temp_addr = addr;
    temp_buf = buffer;

    for (i = 0; i < col; i++) {
        ret = brl_i3c_read_transfer(temp_addr, temp_buf,
            BRL_TRANSFER_MAX_SIZE);
        if (ret)
            return ret;
        temp_addr += BRL_TRANSFER_MAX_SIZE;
        temp_buf += BRL_TRANSFER_MAX_SIZE;
    }
    if (remain > 0)
        ret = brl_i3c_read_transfer(temp_addr, temp_buf, remain);
    return ret;
}

int brl_i3c_write(u32 addr, u8 *buffer, u32 len)
{
    int col;
    int remain;
    int i;
    int ret = -EINVAL;
    u32 temp_addr;
    u8 *temp_buf = NULL;

    col = len / BRL_TRANSFER_MAX_SIZE;
    remain = len % BRL_TRANSFER_MAX_SIZE;
    temp_addr = addr;
    temp_buf = buffer;

    for (i = 0; i < col; i++) {
        ret = brl_i3c_write_transfer(temp_addr, temp_buf,
            BRL_TRANSFER_MAX_SIZE);
        if (ret)
            return ret;
        temp_addr += BRL_TRANSFER_MAX_SIZE;
        temp_buf += BRL_TRANSFER_MAX_SIZE;
    }

    if (remain > 0)
        ret = brl_i3c_write_transfer(temp_addr, temp_buf, remain);
    return ret;
}

struct mxt_tui_data __attribute__((weak)) tui_mxt_data;
int brl_device_init(void)
{
    TP_LOG_INFO("tp_init:brl tui_special_feature_support = 0x%x tui_irq_num:%u tui_irq_gpio:%u\n",
        tui_mxt_data.tui_special_feature_support,
        tui_mxt_data.tui_irq_num, tui_mxt_data.tui_irq_gpio);
    return 0;
}

#define BRL_TOUCH_DATA_ADDR  0x10338
#define BRL_BYTES_PER_COORD 8
#define BRL_TOUCH_EVENT 0x80
#define BRL_SCREEN_X_MAX 1160
#define BYTES_PER_EDGE 6
/* edge info */
#define BRL_EDGE_ADDR 0x10392
#define BRL_SYNC_CMD_LEN 2
static int brl_touch_handler(
    struct ts_tui_fingers *info, u32 touch_num)
{
    int ret = 0;
    u8 buffer[BRL_BYTES_PER_COORD * BRL_MAX_TOUCH] = {0};
    u8 edge_buf[BYTES_PER_EDGE * BRL_MAX_TOUCH] = {0};

    u32 reg = BRL_TOUCH_DATA_ADDR;
    int id;
    int x;
    int y;
    int w;
    u32 i;

    TP_LOG_DEBUG("brl_touch_handler in\n");
    if (touch_num > BRL_MAX_TOUCH) {
        TP_LOG_ERR("brl_touch_handler touch num over max\n");
        ret = -EINVAL;
        return ret;
    }

    (void)memset_s(info, sizeof(struct ts_tui_fingers), 0x00, sizeof(struct ts_tui_fingers));

    reg += BRL_BYTES_PER_COORD;
    ret = brl_i3c_read(reg, buffer, touch_num * BRL_BYTES_PER_COORD);
    if (ret) {
        TP_LOG_ERR("get touch data failed");
        return ret;
    }
    ret = brl_i3c_read(BRL_EDGE_ADDR, edge_buf, touch_num * BYTES_PER_EDGE);
    if (ret) {
        TP_LOG_ERR("get edge data failed\n");
        return ret;
    }

    TP_LOG_DEBUG("brl_touch_handler touch_num = %d\n", touch_num);
    for (i = 0; i < touch_num; i++) {
        /* 2~7 read xyw offset */
        id = (buffer[i * BRL_BYTES_PER_COORD] >> 4) & 0x0f;
        x = buffer[i * BRL_BYTES_PER_COORD + 2] |
            (buffer[i * BRL_BYTES_PER_COORD + 3] << 8);
        y = buffer[i * BRL_BYTES_PER_COORD + 4] |
            (buffer[i * BRL_BYTES_PER_COORD + 5] << 8);
        w = buffer[i * BRL_BYTES_PER_COORD + 6] |
            (buffer[i * BRL_BYTES_PER_COORD + 7] << 8);

        info->fingers[id].x = BRL_SCREEN_X_MAX - x;

        info->fingers[id].y = y;
        info->fingers[id].major = w;
        info->fingers[id].minor = w;
        info->fingers[id].pressure = w;
        info->fingers[id].status = 1;
    }
    info->cur_finger_number = touch_num;
    return ret;
}

int brl_get_data(struct ts_tui_fingers *report_data)
{
    struct ts_tui_fingers *info = NULL;
    int ret;
    int ret_write;
    u8 pre_buf[BRL_BYTES_PER_COORD] = {0};
    u8 sync_val[BRL_SYNC_CMD_LEN] = {0};
    u8 event_status;

    if (report_data == NULL) {
        TP_LOG_ERR("%s: report_data NULL\n", __func__);
        return -EINVAL;
    }

    TP_LOG_DEBUG("brl_get_data in\n");
    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info\n");
        return -EINVAL;
    }

    ret = brl_i3c_read(BRL_TOUCH_DATA_ADDR, pre_buf, sizeof(pre_buf));
    if (ret < 0) {
        TP_LOG_ERR("brl read event head failed\n");
        goto error;
    }

    /* buffer[0]: event state */
    event_status = pre_buf[0];
    TP_LOG_DEBUG("event_status = 0x%x\n", event_status);
    if ((event_status & BRL_TOUCH_EVENT) == BRL_TOUCH_EVENT) {
        ret = brl_touch_handler(info, (pre_buf[2] & 0x0f));
        if (ret < 0)
            TP_LOG_ERR("brl_touch_handler ret error = %d\n", ret);
    }
    ret = ts_tui_algo_t1(info, report_data);
error:
    ret_write = brl_i3c_write(BRL_TOUCH_DATA_ADDR, sync_val, BRL_SYNC_CMD_LEN);
    if (ret_write < 0)
        TP_LOG_ERR("brl write sync cmd failed\n");
    SRE_MemFree(0, info);
    return ret;
}
