/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: parade driver
 * Author: lijie
 * Create: 2017-04-02
 */
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <mem_ops.h>
#include "sre_sys.h"
#include "sre_log.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include "libhwsecurec/securec.h"

extern int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);

enum parade_event_id {
    CY_EV_NO_EVENT,
    CY_EV_TOUCHDOWN,
    CY_EV_MOVE,   /* significant displacement (> act dist) */
    CY_EV_LIFTOFF /* record reports last position */
};
enum parade_object_id {
    CY_OBJ_STANDARD_FINGER,
    CY_OBJ_PROXIMITY,
    CY_OBJ_STYLUS,
    CY_OBJ_HOVER,
    CY_OBJ_GLOVE,
};

int parade_device_init(void)
{
    TP_LOG_ERR("device_init:parade \n");
    return 0;
}

/* **************************************************************
 * parade_get_data(struct ts_tui_fingers *report_data)
 * input:
 * ouput: report_data
 * ==parade touch reports==
 * byte 0-1 :Length = 7 + Number of Records * Record Length
 * byte 2    : Report ID
 * byte 3-4 : Timestamp
 * byte 5     : bit 6-7 reserved , bit 5 LO, bit 0-4 Number of Records
 * byte 6     : bit 6-7 Report Counter , bit 3-5 reserved, bit 0-2 Noise Effects
 * byte 7+ Record Length    : Records 0
 * byte 7+ n*Record Length    : Records n
 * ==Records 0==
 * byte 0    : bit 3-7 reserved, bit 0-2 obj id (touch type)
 * byte 1    : bit 7 tip, , bit 5-6 event id, bit 0-4 touch id
 * byte 2-3 : x
 * byte 4-5 : y
 * byte 6     :Pressure
 * byte 7     :Major axis length(7:0)
 * byte 8     :Minor axis length(15:8)
 * byte 9     :Orientation
 * ***************************************************************/
int parade_get_data(struct ts_tui_fingers *report_data)
{
    int rc;
    unsigned short size;
    unsigned char buf[PARADE_TOUCH_REPORT_MAX_SIZE] = {0};
    u8 reg_addr = PAR_REG_BASE;
    int report_id;
    int i;
    int position;
    unsigned char input_id;
    unsigned char event_id;
    unsigned char obj_id;
    int rec_num;
    struct ts_tui_fingers *info;

    if (report_data == NULL)
        return -1;

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return -1;
    }

    buf[0] = reg_addr;
    rc = ts_tui_i2c_read(buf, (PARADE_TOUCH_REPORT_MAX_SIZE - 1), I2C_PARADE_ADDR);
    if (rc < 0) {
        TP_LOG_ERR("%s, fail read  rc=%d\n", __func__, rc);
        goto out;
    }
    /* get frame size */
    size = (buf[OFFSET_BYTE1] << OFFSET_BYTE8) | buf[0];
    /* error packets if data size = 2 means data error */
    if ((size == 0) || (size == 2) || (size > (PARADE_TOUCH_REPORT_MAX_SIZE - 1))) {
        TP_LOG_ERR("%s: Data size error!size = %d\n", __func__, size);
        goto out;
    }
    // get report id
    report_id = buf[OFFSET_BYTE2];
    if (report_id != HID_TOUCH_REPORT_ID) {
        TP_LOG_ERR("%s: report_id error!HID_TOUCH_REPORT_ID = %d\n", __func__, HID_TOUCH_REPORT_ID);
        goto out;
    }

    for (i = 0; i < TOUCH_MAX_FINGER_NUM; i++)
        info->fingers[i].status = 0;

    // get records num
    rec_num = buf[OFFSET_BYTE5] & 0x1F;
    if (rec_num > TOUCH_MAX_FINGER_NUM)
        rec_num = TOUCH_MAX_FINGER_NUM;

    for (i = 0; i < rec_num; i++) {
        // header 7 byte  9 is the length of rec
        position = PARADE_TOUCH_REPORT_FRAME_OFFSET + 9 * i;
        // touch id
        input_id = buf[position + 1] & 0x1F;
        if (input_id >= TOUCH_MAX_FINGER_NUM) {
            TP_LOG_ERR("%s: max finger id support is 10\n", __func__);
            continue;
        }
        obj_id = buf[position] & 0x7;
        event_id = (buf[position + OFFSET_BYTE1] >> OFFSET_BYTE5) & 0x3;

        info->fingers[input_id].event = event_id;
        switch (event_id) {
        // PATCH: Huawei does not use our event, they use x=0 or y=0 as this id lift off event
        case CY_EV_LIFTOFF:
            info->fingers[input_id].x = 0;
            info->fingers[input_id].y = 0;
            break;
        case CY_EV_TOUCHDOWN:
        case CY_EV_NO_EVENT:
        case CY_EV_MOVE:
            info->fingers[input_id].x =
                (buf[position + OFFSET_BYTE2] | (buf[position + OFFSET_BYTE3] << OFFSET_BYTE8)) & 0xFFFF;
            info->fingers[input_id].y =
                (buf[position + OFFSET_BYTE4] | (buf[position + OFFSET_BYTE5] << OFFSET_BYTE8)) & 0xFFFF;
            break;
        }

        info->fingers[input_id].pressure = buf[position + OFFSET_BYTE6];
        switch (obj_id) { /* Detect the object type */
        case CY_OBJ_STANDARD_FINGER:
            info->fingers[input_id].status = FINGER_ENTER;
            break;
        case CY_OBJ_GLOVE:
            info->fingers[input_id].status = GLOVE_TOUCH;
            break;
        case CY_OBJ_STYLUS:
            info->fingers[input_id].status = FINGER_MOVING;
            break;
        }
        info->fingers[input_id].major = buf[position + OFFSET_BYTE7] & 0xFF;
        info->fingers[input_id].minor = buf[position + OFFSET_BYTE8] & 0xFF;
        info->fingers[input_id].orientation = buf[position + OFFSET_BYTE9];
    }

    info->cur_finger_number = rec_num;
    ts_tui_algo_t1(info, report_data);
out:
    SRE_MemFree(0, info);
    return rc;
}
