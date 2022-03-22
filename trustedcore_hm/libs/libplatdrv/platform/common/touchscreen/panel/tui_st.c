/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tui st tp driver
 * Author: Chen puwang
 * Create: 2020-04-20
 */

#include "libhwsecurec/securec.h"
#include <legacy_mem_ext.h>
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include <gpio.h>
#include <platform_touchscreen.h>
#include "tui_panel.h"


#define FTS_FIFO_MAX 32
#define FTS_EVENT_SIZE 8
#define COUNT_MAX 100000

#define ABS_MAX_X 1440
#define ABS_MAX_Y 2560
/*
 * Commands
 */
#define READ_ONE_EVENT 0x85
#define READ_ALL_EVENT 0x86
/*
 * Events ID
 */
#define EVENTID_NO_EVENT 0x00
#define EVENTID_ENTER_POINTER 0x03
#define EVENTID_LEAVE_POINTER 0x04
#define EVENTID_MOTION_POINTER 0x05
#define EVENTID_HOVER_ENTER_POINTER 0x07
#define EVENTID_HOVER_LEAVE_POINTER 0x08
#define EVENTID_HOVER_MOTION_POINTER 0x09
#define EVENTID_PROXIMITY_ENTER 0x0B
#define EVENTID_PROXIMITY_LEAVE 0x0C
#define EVENTID_BUTTON_STATUS 0x0E
#define EVENTID_ERROR 0x0F
#define EVENTID_CONTROLLER_READY 0x10
#define EVENTID_RESULT_READ_REGISTER 0x12
#define EVENTID_SW_CONFIG_READ 0x12
#define EVENTID_COMP_DATA_READ 0x13
#define EVENTID_STATUS 0x16
#define EVENTID_GESTURE 0x20
#define EVENTID_PEN_ENTER 0x23
#define EVENTID_PEN_LEAVE 0x24
#define EVENTID_PEN_MOTION 0x25
#define EVENTID_ORIENTATION 0x27
#define EVENTID_LAST (EVENTID_ORIENTATION + 1)

/*
 * Event installer helpers
 */
#define event_id(_e) EVENTID_##_e
#define handler_name(_h) st_##_h##_event_handler
#define install_handler(_i, _evt, _hnd) do { \
        (_i)->event_dispatch_table[event_id(_evt)] = handler_name(_hnd); \
    } while (0)

typedef unsigned char *(*event_dispatch_handler_t)(unsigned char *data, struct ts_tui_fingers *report_data);

struct fts_tui_info {
    event_dispatch_handler_t *event_dispatch_table;
};

static struct fts_tui_info *g_st_tui_info = NULL;
static unsigned int g_need_report;
static void st_get_eventid(struct ts_tui_fingers *report_data);

int st_get_data(struct ts_tui_fingers *report_data)
{
    unsigned int value;
    unsigned count = 0;

    TP_LOG_DEBUG("st get data\n");
    g_need_report = false;
    if (report_data == NULL) {
        TP_LOG_ERR("report_data is NULL\n");
        return -1;
    }

    st_get_eventid(report_data);
    if (g_need_report)
        ts_tui_algo_t1(report_data, report_data);

    value = gpio_get_value(TS_GPIO_IRQ);
    while (!value) {
        value = gpio_get_value(TS_GPIO_IRQ);
        if (value || count > COUNT_MAX)
            break;
        else
            count++;
    }

    return 0;
}

static void st_set_event_to_fingers(int x, int y, int major, int minor, int pressure, int status, unsigned char touchid,
    unsigned char touchcount, struct ts_tui_fingers *report_data)
{
    TP_LOG_DEBUG("%s: z:%d, status:%d, touchid:%d, touchcount:%d\n", __func__, pressure, status, touchId, touchcount);
    /* max finger 10 */
    if (touchid >= 10)
        touchid = 0;

    if (report_data->fingers[touchid].pressure == 0xEFFE) {
        TP_LOG_ERR("Not handle pointer event, has handled leave event\n");
        return;
    }

    if (memset_s(&report_data->fingers[touchid], sizeof(struct ts_tui_finger), 0, sizeof(struct ts_tui_finger)))
        TP_LOG_ERR("memset error\n");

    report_data->cur_finger_number = 0;
    report_data->fingers[touchid].x = x;
    report_data->fingers[touchid].y = y;
    report_data->fingers[touchid].major = major;
    report_data->fingers[touchid].minor = minor;
    report_data->fingers[touchid].pressure = pressure;
    report_data->fingers[touchid].status = status;
    report_data->cur_finger_number += touchcount;

    return;
}

/* EventId : 0x00 */
static inline unsigned char *st_next_event(unsigned char *evt)
{
    /* Nothing to do with this event, moving to the next one */
    evt += FTS_EVENT_SIZE;

    /* the previous one was the last event ?  */
    return (evt[-1] & 0x1F) ? evt : NULL;
}

static unsigned char *st_nop_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    TP_LOG_DEBUG("Doing nothing for event 0x%x\n", *event);
    (void)report_data;
    return (unsigned char *)st_next_event(event);
}

/* EventId : 0x03 */
static unsigned char *st_enter_pointer_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    unsigned char touchid;
    unsigned char touchcount;
    int x;
    int y;
    int status;
    int major;
    int minor;

    g_need_report = true;
    TP_LOG_DEBUG("come in st_enter_pointer_event_handler\n");
    touchid = event[1] & 0x0F;
    touchcount = (event[1] & 0xF0) >> OFFSET_BYTE4;
    x = (event[OFFSET_BYTE2] << OFFSET_BYTE4) | ((event[OFFSET_BYTE4] & 0xF0) >> OFFSET_BYTE4);
    y = (event[OFFSET_BYTE3] << OFFSET_BYTE4) | (event[OFFSET_BYTE4] & 0x0F);
    status = (event[OFFSET_BYTE5] & 0xE0) >> OFFSET_BYTE5; /* bit5-bit7:finger status */
    major = (event[OFFSET_BYTE5] & 0x1F);                  /* bit0-bit4: major */
    minor = event[OFFSET_BYTE6];                           /* event6:minor */
    if (x == ABS_MAX_X)
        x--;
    if (y == ABS_MAX_Y)
        y--;
    st_set_event_to_fingers(x, y, major, minor, 1, status, touchid, touchcount, report_data);
    return st_next_event(event);
}

/* EventId : 0x04 */
static unsigned char *st_leave_pointer_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    TP_LOG_DEBUG("%s: Received event 0x%x\n", __func__, event[0]);
    g_need_report = true;

    unsigned char touchid, touchcount;

    touchid = event[1] & 0x0F;
    touchcount = (event[1] & 0xF0) >> OFFSET_BYTE4;

    st_set_event_to_fingers(0, 0, 0, 0, 0xEFFE, 1, touchid, touchcount, report_data);

    return st_next_event(event);
}

/* EventId : 0x05 */
#define st_motion_pointer_event_handler st_enter_pointer_event_handler

static int st_tui_interrupt_install(struct fts_tui_info *info)
{
    int i;

    if (info == NULL) {
        TP_LOG_ERR("info is NULL\n");
        return -1;
    }
    info->event_dispatch_table = SRE_MemAlloc(0, 0, sizeof(event_dispatch_handler_t) * EVENTID_LAST);

    if (!info->event_dispatch_table) {
        TP_LOG_ERR("event dispatch table malloc failed\n");
        return -1;
    }

    for (i = 0; i < EVENTID_LAST; i++)
        info->event_dispatch_table[i] = st_nop_event_handler;
    install_handler(info, ENTER_POINTER, enter_pointer);
    install_handler(info, LEAVE_POINTER, leave_pointer);
    install_handler(info, MOTION_POINTER, motion_pointer);
    return 0;
}

int st_device_init(void)
{
    TP_LOG_DEBUG("st_device_init\n");

    g_st_tui_info = SRE_MemAlloc(0, 0, sizeof(struct fts_tui_info));
    if (g_st_tui_info == NULL) {
        TP_LOG_ERR("malloc failed!\n");
        return -1;
    }
    if (st_tui_interrupt_install(g_st_tui_info)) {
        SRE_MemFree(0, g_st_tui_info);
        return -1;
    }
    return 0;
}

/*
 * New Interrupt handle implementation
 */
static void st_get_eventid(struct ts_tui_fingers *report_data)
{
    int error;
    int error1;
    unsigned int left_events;
    unsigned char *data;
    unsigned char *temp_data;
    unsigned char *event;
    unsigned char eventid;
    event_dispatch_handler_t event_handler;
    unsigned int size = FTS_EVENT_SIZE * (FTS_FIFO_MAX + 1);

    data = (unsigned char *)SRE_MemAlloc(0, 0, size);
    if (data == NULL) {
        TP_LOG_ERR("data malloc failed\n");
        return;
    }

    temp_data = (unsigned char *)SRE_MemAlloc(0, 0, size);
    if (temp_data == NULL) {
        TP_LOG_ERR("temp_data malloc failed\n");
        SRE_MemFree(0, data);
        return;
    }

    if (memset_s(data, size, 0, size))
        goto exit;

    if (memset_s(temp_data, size, 0, size))
        goto exit;

    /*
     * to avoid reading all FIFO, we read the first event and
     * then check how many events left in the FIFO
     */
    data[0] = READ_ONE_EVENT;
    error = hisi_i2c_read(I2C_ADDR, data, FTS_EVENT_SIZE, 0x49);
    if (!error) {
        left_events = data[OFFSET_BYTE7] & 0x1F;
        if ((left_events > 0) && (left_events < FTS_FIFO_MAX)) {
            /*
             * Read remaining events.
             */
            temp_data[0] = READ_ALL_EVENT;
            error1 = hisi_i2c_read(I2C_ADDR, temp_data, (left_events + 1) * FTS_EVENT_SIZE, 0x49);
            if (memcpy_s(&data[FTS_EVENT_SIZE], size - FTS_EVENT_SIZE, temp_data, (left_events + 1) * FTS_EVENT_SIZE)) {
                TP_LOG_ERR("copy error\n");
                goto exit;
            }
            /*
             * Got an error reading remining events,
             * process at least * the first one that was
             * raeding fine.
             */
            if (error1)
                data[OFFSET_BYTE7] &= 0xE0;
        }

        /* At least one event is available */
        event = data;
        do {
            eventid = *event;
            event_handler = g_st_tui_info->event_dispatch_table[eventid];

            if (eventid < EVENTID_LAST)
                event = event_handler((event), report_data);
            else
                event = st_next_event(event);
        } while (event);
    } else {
        TP_LOG_ERR("i2c read error\n");
    }
exit:
    SRE_MemFree(0, data);
    SRE_MemFree(0, temp_data);
    return;
}


void tui_st_exit(void)
{
    if (g_st_tui_info) {
        if (g_st_tui_info->event_dispatch_table) {
            SRE_MemFree(0, g_st_tui_info->event_dispatch_table);
            g_st_tui_info->event_dispatch_table = NULL;
        }
    }
    if (g_st_tui_info) {
        SRE_MemFree(0, g_st_tui_info);
        g_st_tui_info = NULL;
    }
    return;
}
