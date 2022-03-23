/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: amtel driver
 * Author: lijie
 * Create: 2017-04-02
 */
#include <legacy_mem_ext.h>
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"

/* MXT_GEN_MESSAGE_T5 object */
#define MXT_RPTID_NOMSG 0xff
#define MXT_T100_DETECT (1 << 7)

#define MXT_T100_EVENT_MASK 0x0f
#define MXT_T100_EVENT_NO_EVENT 0
#define MXT_T100_EVENT_MOVE 1
#define MXT_T100_EVENT_DOWN 4
#define MXT_T100_EVENT_UP 5

struct scr_info {
    u8 status;
    u8 num_tch;
    u16 area_tch;
    u16 area_atch;
    u16 area_inttch;
};

struct ext_info {
    u8 status;
    u8 amp;
    u8 vec;
    u8 area;
    u8 peak;
    u8 width;
    u8 height;
};

static u8 *mxt_msg_buf = NULL;
static int mxt_cur_finger_number = 0;
static int mxt_t100_int = 1;
struct mxt_tui_data __attribute__((weak)) tui_mxt_data;
extern int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);

static void parse_t100_scr_message(const u8 *message, struct scr_info *in)
{
    u8 aux = 1;

    if ((message == NULL) || (in == NULL))
        return;
    if (memset_s(in, sizeof(struct scr_info), 0, sizeof(struct scr_info)))
        return;
    in->status = message[aux++];
    in->num_tch = message[aux++];
}

static void mxt_proc_t100_message_number(struct mxt_tui_data *data, u8 *message, struct ts_tui_fingers *report_data)
{
    int id;
    u8 val_buffer_r[1];
    u16 addr;
    int ret;
    struct scr_info info;

    if ((data == NULL) || (message == NULL) || (report_data == NULL))
        return;

    id = (message[0] - data->reportid.t100_reportid_min) - 2; /* should reduce 2 for id */

    /* -2 is illegal */
    if (id != -2) {
        TP_LOG_DEBUG("T100 [%d] msg : 0x%x\n", id, message[1]);
        return;
    }

    parse_t100_scr_message(message, &info);
    TP_LOG_DEBUG("[scr] status:0x%x  [num]:%d [area]:%d %d %d\n", message[1], info.num_tch, info.area_tch,
        info.area_atch, info.area_inttch);

    addr = data->t100_address + 1;
    val_buffer_r[0] = (u8)addr;
    ret = hisi_i2c_read(I2C_ADDR, val_buffer_r, sizeof(val_buffer_r), data->addr);
    if (ret) {
        TP_LOG_ERR("read 0x%x fail\n", addr);
        return;
    }

    mxt_cur_finger_number = info.num_tch;
    TP_LOG_DEBUG("[mxt_proc_t100_message_number]: mxt_cur_finger_number is %d\n", mxt_cur_finger_number);
} /* lint !e715 */

static void parse_t100_ext_message(const u8 *message, struct ext_info *in)
{
    if ((in == NULL) || (message == NULL))
        return;

    if (memset_s(in, sizeof(struct ext_info), 0, sizeof(struct ext_info)))
        TP_LOG_ERR("memset error\n");
    in->status = message[1];

    if (!(in->status & MXT_T100_DETECT))
        return;

    in->amp++;
}

static void mxt_proc_t100_message(struct mxt_tui_data *data, u8 *message, struct ts_tui_fingers *report_data)
{
    int id;
    u8 status;
    int x;
    int y;
    struct ext_info e_info;

    if ((data == NULL) || (message == NULL) || (report_data == NULL))
        return;

    /* do not report events if input device not yet registered */
    id = (message[0] - data->reportid.t100_reportid_min) - 2; /* should reduce 2 for id */
    /* ignore SCRSTATUS events */
    if (id < 0) {
        TP_LOG_DEBUG("T100 [%d] SCRSTATUS : 0x%x\n", id, message[1]);
        return;
    }

    status = message[1];
    x = (message[OFFSET_BYTE3] << OFFSET_BYTE8) | message[OFFSET_BYTE2];
    y = (message[OFFSET_BYTE5] << OFFSET_BYTE8) | message[OFFSET_BYTE4];
    parse_t100_ext_message(message, &e_info);
    TP_LOG_DEBUG("[%d] readstatus:0x%x [amp]:0x%x [vec]:0x%x [area]:0x%x [peak]:0x%x [width]:0x%x [height]:0x%x\n", id,
        status, e_info.amp, e_info.vec, e_info.area, e_info.peak, e_info.width, e_info.height);

    if (status & MXT_T100_DETECT) {
        /*
         * A reported size of zero indicates that the reported touch
         * is a stylus from a linked Stylus T47 object.
         */
        report_data->fingers[id].status = (status & MXT_T100_EVENT_MASK);
        if ((report_data->fingers[id].status == MXT_T100_EVENT_DOWN) ||
            (report_data->fingers[id].status == MXT_T100_EVENT_MOVE) ||
            (report_data->fingers[id].status == MXT_T100_EVENT_NO_EVENT)) {
            report_data->fingers[id].status = TS_FINGER_PRESS;
        } else if (report_data->fingers[id].status == MXT_T100_EVENT_UP) {
            report_data->fingers[id].status = TS_FINGER_RELEASE;
        } else {
            TP_LOG_DEBUG("unknown status:%d\n", report_data->fingers[id].status);
            report_data->fingers[id].status = 0;
        }
        report_data->cur_finger_number = mxt_cur_finger_number;
        /* Touch active */
        report_data->fingers[id].x = x;
        report_data->fingers[id].y = y;
        report_data->fingers[id].pressure = 1;
    }
}

static int mxt_proc_message(struct mxt_tui_data *data, u8 *message, struct ts_tui_fingers *report_data)
{
	unsigned char report_id;
	if ((data == NULL) || (message == NULL) || (report_data == NULL))
        return ERROR;

    report_id = message[0];

    if (report_id == MXT_RPTID_NOMSG)
        return 0;

    TP_LOG_DEBUG("mxt_proc_message  report_id is 0x%x, t100_reportid_min is 0x%x, t100_reportid_max is 0x%x\n",
        report_id, data->reportid.t100_reportid_min, data->reportid.t100_reportid_max);
    if (report_id >= data->reportid.t100_reportid_min && report_id <= data->reportid.t100_reportid_max) {
        if (report_id < (data->reportid.t100_reportid_min + OFFSET_BYTE2))
            mxt_proc_t100_message_number(data, message, report_data);
        else
            mxt_proc_t100_message(data, message, report_data);
        mxt_t100_int = 1;
    }
    return 1;
}

static int mxt_read_and_process_messages(struct mxt_tui_data *data, u8 count, struct ts_tui_fingers *report_data)
{
    int ret;
    int i;
    u8 num_valid = 0;

    if ((data == NULL) || (report_data == NULL))
        return ERROR;

    /* Safety check for msg_buf */
    if (count > data->max_reportid)
        return ERROR;

    /* Process remaining messages if necessary */
    mxt_msg_buf[0] = data->t5_address & 0xff;
    mxt_msg_buf[1] = (data->t5_address >> OFFSET_BYTE8) & 0xff;
    ret = hisi_i2c_read_reg16(I2C_ADDR, mxt_msg_buf, data->t5_msg_size * count, data->addr);
    if (ret) {
        TP_LOG_ERR("Failed to read %u messages %d\n", count, ret);
        return ret;
    }

    for (i = 0; i < count; i++) {
        ret = mxt_proc_message(data, mxt_msg_buf + data->t5_msg_size * i, report_data);
        if (ret == 1)
            num_valid++;
    }

    /* return number of messages read */
    return num_valid;
}

static int mxt_process_messages_t44(struct mxt_tui_data *data, struct ts_tui_fingers *report_data)
{
    int ret;
    u8 count, num_left;

    if ((data == NULL) || (report_data == NULL))
        return ERROR;

    /* Read T44 and T5 together */
    mxt_msg_buf[0] = data->t44_address & 0xff;
    mxt_msg_buf[1] = (data->t44_address >> OFFSET_BYTE8) & 0xff;
    ret = hisi_i2c_read_reg16(I2C_ADDR, mxt_msg_buf, data->t5_msg_size + 1, data->addr);
    if (ret) {
        TP_LOG_DEBUG("Failed to read T44 and T5 %d\n", ret);
        return ret;
    }

    count = mxt_msg_buf[0];

    if (count == 0) {
        TP_LOG_DEBUG("Interrupt triggered but zero messages\n");
        return 0;
    } else if (count > data->max_reportid) {
        TP_LOG_DEBUG("T44 count %d exceeded max report id\n", count);
        count = data->max_reportid;
    }

    /* Process first message, T5 */
    ret = mxt_proc_message(data, mxt_msg_buf + 1, report_data);
    if (ret < 0) {
        TP_LOG_DEBUG("Unexpected invalid message\n");
        return ret;
    }

    num_left = count - 1;

    /* Process remaining messages if necessary */
    if (num_left) {
        ret = mxt_read_and_process_messages(&tui_mxt_data, num_left, report_data);
        if (ret < 0)
            goto end;
        else if (ret != num_left)
            TP_LOG_ERR("Unexpected invalid message\n");
    } /* lint !e548 */

end:
    return 0;
}

int atmel_get_data(struct ts_tui_fingers *report_data)
{
    if (report_data == NULL)
        return ERROR;

    TP_LOG_DEBUG("atmel get data\n");
    TP_LOG_DEBUG("max_reportid is 0x%x, t5_address is 0x%x, t5_msg_size is 0x%x, t44_address is 0x%x, t100_address is "
                 "0x%x, t100_reportid_min is 0x%x, t100_reportid_max is 0x%x, addr is0x%x\n",
        tui_mxt_data.max_reportid, tui_mxt_data.t5_address, tui_mxt_data.t5_msg_size, tui_mxt_data.t44_address,
        tui_mxt_data.t100_address, tui_mxt_data.t100_reportid_min, tui_mxt_data.t100_reportid_max, tui_mxt_data.addr);
    mxt_t100_int = 0;
    if (mxt_process_messages_t44(&tui_mxt_data, report_data) != 0)
        return ERROR;

    if (mxt_t100_int)
        ts_tui_algo_t1(report_data, report_data);
    return 0;
}

int atmel_device_init(void)
{
    TP_LOG_DEBUG("atmel_device_init:name is %s\n", tui_mxt_data.device_name);
    TP_LOG_DEBUG("max_reportid is 0x%x, t5_address is 0x%x, t5_msg_size is 0x%x, t44_address is 0x%x, t100_address is "
                 "0x%x, t100_reportid_min is 0x%x, t100_reportid_max is 0x%x, addr is0x%x\n",
        tui_mxt_data.max_reportid, tui_mxt_data.t5_address, tui_mxt_data.t5_msg_size, tui_mxt_data.t44_address,
        tui_mxt_data.t100_address, tui_mxt_data.t100_reportid_min, tui_mxt_data.t100_reportid_max, tui_mxt_data.addr);
    TP_LOG_DEBUG("alloc size is %d\n", tui_mxt_data.max_reportid * tui_mxt_data.t5_msg_size);
    mxt_msg_buf = SRE_MemAlloc(0, 0, tui_mxt_data.max_reportid * tui_mxt_data.t5_msg_size);
    if (!mxt_msg_buf) {
        TP_LOG_ERR("Failed to allocate message buffer\n");
        return ERROR;
    }
    return 0;
}

void tui_atmel_exit(void)
{
    if (mxt_msg_buf)
        SRE_MemFree(0, mxt_msg_buf);
    mxt_msg_buf = NULL;
}
