/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tui st tp driver
 * Author: Chen puwang
 * Create: 2020-04-20
 */
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include <gpio.h>
#include "tui_panel.h"
#include <platform_touchscreen.h>
#include <tui_drv/tui_drv_types.h>
#include "libhwsecurec/securec.h"
#include "hisi_tui_touchscreen.h"
#define ST_SLAVE_ADDR 0x49

#define FTS_FIFO_MAX 32
#define FTS_EVENT_SIZE 8

/*
 * Commands
 */
#define READ_ALL_EVENT 0x86

/*
 * Events ID
 */
#define EVT_ID_NOEVENT 0x00     /* No Events */
#define EVT_ID_ENTER_POINT 0x13 /* Touch enter in the sensing area */
/* Touch motion (a specific touch changed position) */
#define EVT_ID_MOTION_POINT 0x23
#define EVT_ID_LEAVE_POINT 0x33 /* Touch leave the sensing area */
#define EVT_ID_DEBUG 0xE3       /* Debug Info */
#define EVT_ID_ERROR 0xF3       /* Error Event */

/* Max number of unique event IDs supported */
#define NUM_EVT_ID (((EVT_ID_ERROR & 0xF0) >> 4) + 1)

#define STATUS_GLOVE_MODE 6
#define STATUS_FINGER_MODE 1
#define ENTER_POINT_MAJOR 1
#define ENTER_POINT_MINOR 1
#define ENTER_POINT_PRESSURE 1
#define LEAVE_POINT_MAJOR 0
#define LEAVE_POINT_MINOR 0
#define LEAVE_POINT_STATUS 1
#define LEAVE_POINT_PRESSURE 0xEFFE
#define LEFT_EVENTS_POS 7
#define LEFT_EVENTS_MASK 0x1F
#define X_HI_POS 3
#define X_LOW_POS 2
#define Y_HI_POS 4
#define Y_LOW_POS 3
#define TOUCH_ID_POS 1
#define TOUCH_COUNT_LOW_POS 5
#define TOUCH_COUNT_HI_POS 7
#define TOUCH_COUNT_MASK 0xC0
#define HIGH_BITS_MASK 0xF0
#define LOW_BITS_MASK 0x0F
#define TP_DISPLAY_EXPAND 1
#define TP_DISPLAY_MAIN 2
#define TP_DISPLAY_SUB 3
#define DISPLAY_MAIN_Y_MAX 1130
#define DISPLAY_Y_MAX 2200
#define DISPLAY_SUB_Y_MIN 1310
#define DISPLAY_SUB_Y_MAX 2200
/* bit4~bit7 is touch id */
#define TOUCH_ID_BIT 4
#define FINGER_ID_INIT_STATE 0
#define FINGER_RELEASE_STATE 1

#define event_id(_e) (EVT_ID_##_e >> OFFSET_BYTE4)
#define handler_name(_h) st_##_h##_event_handler

#define install_handler(_i, _evt, _hnd) { \
        (_i)->event_dispatch_table[event_id(_evt)] = handler_name(_hnd); \
    }

typedef void (*event_dispatch_handler_t)(unsigned char *data, struct ts_tui_fingers *report_data);

struct fts_tui_info {
    event_dispatch_handler_t *event_dispatch_table;
};

static unsigned int g_report_touchid;
static struct fts_tui_info *g_st_tui_info;
static unsigned int g_need_report;
static int g_finger_release;

static void st_get_eventid(struct ts_tui_fingers *report_data);

/* exchange byte 32bit */
static __inline uint32_t bswap_32(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & 0xff00) |
        ((x << 8) & 0xff0000) | (x << 24);
}

uint32_t htonl(uint32_t n)
{
    union {
        int i;
        char c;
    }
    u = {1};
    return u.c ? bswap_32(n) : n;
}

static void tui_report_fingers_init(struct effective_fingers *report_fingers)
{
    int ret;
    struct tui_panel_info_k tui_fold_info = { 0 };

    if (!report_fingers) {
        TP_LOG_ERR("%s report_fingers null\n", __func__);
        return;
    }
    ret = get_fold_screen(&tui_fold_info);
    if (ret < 0) {
        TP_LOG_ERR("%s get_fold_screen fail\n", __func__);
        return;
    }
    TP_LOG_ERR("%s display_state %d\n", __func__, tui_fold_info.display_state);
    switch (tui_fold_info.display_state) {
    case TP_DISPLAY_EXPAND:
        report_fingers->y0 = 0;
        report_fingers->y1 = DISPLAY_Y_MAX;
        break;
    case TP_DISPLAY_MAIN:
        report_fingers->y0 = 0;
        report_fingers->y1 = DISPLAY_MAIN_Y_MAX;
        break;
    case TP_DISPLAY_SUB:
        report_fingers->y0 = DISPLAY_SUB_Y_MIN;
        report_fingers->y1 = DISPLAY_SUB_Y_MAX;
        break;
    default:
        TP_LOG_ERR("%s default\n", __func__);
        break;
    }
}

static void tui_report_effective_fingers(struct ts_tui_fingers *report_data)
{
    int i;
    struct effective_fingers report_fingers = { 0, DISPLAY_Y_MAX };

    TP_LOG_DEBUG("%s\n", __func__);
    if (!report_data) {
        TP_LOG_ERR("report_data null\n", __func__);
        return;
    }
    tui_report_fingers_init(&report_fingers);
    for (i = 0; i < TS_TUI_MAX_FINGER; i++) {
        if ((report_data->fingers[i].y >= report_fingers.y0) && (report_data->fingers[i].y <= report_fingers.y1)) {
            report_data->fingers[0].x = report_data->fingers[i].x;
            report_data->fingers[0].y = report_data->fingers[i].y;
            report_data->fingers[0].pressure = report_data->fingers[i].pressure;
            g_report_touchid = i;
            TP_LOG_DEBUG("%s p=%d touchid=%d\n", __func__, report_data->fingers[0].pressure, i);
            return;
        }
    }
    TP_LOG_DEBUG("%s end\n", __func__);
    report_data->fingers[0].x = 0;
    report_data->fingers[0].y = 0;
    report_data->fingers[0].status = TS_FINGER_RELEASE;
    report_data->fingers[0].pressure = 0;
    report_data->cur_finger_number = 0;
}

int st_get_data_new(struct ts_tui_fingers *report_data)
{
    TP_LOG_DEBUG("st get data\n");
    g_need_report = false;
    g_finger_release = 0;

    if (!report_data) {
        TP_LOG_ERR("report_data is NULL\n");
        return -EINVAL;
    }

    st_get_eventid(report_data);
    TP_LOG_INFO("%s g_finger_release %d finger_number %d g_need_report %d\n", __func__, g_finger_release,
        report_data->cur_finger_number, g_need_report);
    if (g_finger_release)
        report_data->cur_finger_number = 0;
    else
        tui_report_effective_fingers(report_data);
    if (g_need_report)
        ts_tui_algo_t1(report_data, report_data);

    return 0;
}

static void st_set_event_to_fingers(int x, int y, int major, int minor, int pressure, int status,
    unsigned char touch_id, unsigned char touchcount, struct ts_tui_fingers *report_data)
{
    int ret;

    TP_LOG_DEBUG("%s: z:%d, status:%d, touch_id:%d, touchcount:%d\n", __func__, pressure, status, touch_id, touchcount);
    if (touch_id >= TOUCH_MAX_FINGER_NUM)
        touch_id = TOUCH_MAX_FINGER_NUM - 1;

    if (report_data->fingers[touch_id].pressure == LEAVE_POINT_PRESSURE) {
        TP_LOG_ERR("not pointer event,has handled leave event id %d\n", touch_id);
        return;
    }

    if ((touch_id == g_report_touchid) && (pressure == LEAVE_POINT_PRESSURE)) {
        TP_LOG_ERR("%s touch id %d\n", __func__, touch_id);
        report_data->cur_finger_number = 0;
        return;
    }

    ret = memset_s(&report_data->fingers[touch_id], sizeof(struct ts_tui_finger), 0, sizeof(struct ts_tui_finger));
    if (ret)
        TP_LOG_ERR("memset error\n");

    report_data->cur_finger_number = 0;
    report_data->fingers[touch_id].x = x;
    report_data->fingers[touch_id].y = y;
    report_data->fingers[touch_id].major = major;
    report_data->fingers[touch_id].minor = minor;
    report_data->fingers[touch_id].pressure = pressure;
    report_data->fingers[touch_id].status = status;
    report_data->cur_finger_number += touchcount;
}

/* EventId : 0x00 */
static void st_nop_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    TP_LOG_DEBUG("Doing nothing for event 0x%x\n", *event);
    (void)report_data;
    (void)event;
}

/* EventId : 0x13 */
static void st_enter_pointer_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    unsigned char touchId;
    unsigned char touchcount;
    int x;
    int y;

    TP_LOG_DEBUG("come in st_enter_pointer_event_handler\n");
    g_need_report = true;

    /* bit4~bit7 is touch id */
    touchId = (event[TOUCH_ID_POS] & HIGH_BITS_MASK) >> OFFSET_BYTE4;
    touchcount = ((event[TOUCH_COUNT_LOW_POS] & TOUCH_COUNT_MASK) >> OFFSET_BYTE6) |
        ((event[TOUCH_COUNT_HI_POS] & TOUCH_COUNT_MASK) >> OFFSET_BYTE4);

    x = (((unsigned int)event[X_HI_POS] & LOW_BITS_MASK) << OFFSET_BYTE8) | (event[X_LOW_POS]);
    y = ((unsigned int)event[Y_HI_POS] << OFFSET_BYTE4) | ((event[Y_LOW_POS] & HIGH_BITS_MASK) >> OFFSET_BYTE4);

    st_set_event_to_fingers(x, y, ENTER_POINT_MAJOR, ENTER_POINT_MINOR, ENTER_POINT_PRESSURE, STATUS_FINGER_MODE,
        touchId, touchcount, report_data);
}

/* EventId : 0x33 */
static void st_leave_pointer_event_handler(unsigned char *event, struct ts_tui_fingers *report_data)
{
    unsigned char touch_id;
    unsigned char touchcount;

    TP_LOG_DEBUG("%s: Received event 0x%x\n", __func__, event[0]);
    g_need_report = true;

    /* bit4~bit7 is touch id */
    touch_id = (event[TOUCH_ID_POS] & HIGH_BITS_MASK) >> TOUCH_ID_BIT;
    touchcount = ((event[TOUCH_COUNT_LOW_POS] & TOUCH_COUNT_MASK) >> OFFSET_BYTE6) |
        ((event[TOUCH_COUNT_HI_POS] & TOUCH_COUNT_MASK) >> OFFSET_BYTE4);
    /*
     * that the released finger ID is the reported ID
     * init fingers state
     */
    if (touch_id == g_report_touchid) {
        g_finger_release = FINGER_RELEASE_STATE;
        g_report_touchid = FINGER_ID_INIT_STATE;
    }

    st_set_event_to_fingers(0, 0, LEAVE_POINT_MAJOR, LEAVE_POINT_MINOR, LEAVE_POINT_PRESSURE, LEAVE_POINT_STATUS,
        touch_id, touchcount, report_data);
}

/* EventId : 0x23 */
#define st_motion_pointer_event_handler st_enter_pointer_event_handler

static int st_tui_interrupt_install(struct fts_tui_info *info)
{
    int i;

    if (!info) {
        TP_LOG_ERR("info is NULL\n");
        return -EINVAL;
    }
    info->event_dispatch_table = malloc(sizeof(event_dispatch_handler_t) * NUM_EVT_ID);

    if (!info->event_dispatch_table) {
        TP_LOG_ERR("event dispatch table malloc failed\n");
        return -EINVAL;
    }

    for (i = 0; i < NUM_EVT_ID; i++)
        info->event_dispatch_table[i] = st_nop_event_handler;

    install_handler(info, ENTER_POINT, enter_pointer);
    install_handler(info, LEAVE_POINT, leave_pointer);
    install_handler(info, MOTION_POINT, motion_pointer);

    return 0;
}

int st_device_init_new(void)
{
    g_st_tui_info = malloc(sizeof(struct fts_tui_info));
    if (!g_st_tui_info) {
        TP_LOG_ERR("malloc failed!\n");
        return -ENOMEM;
    }
    if (st_tui_interrupt_install(g_st_tui_info)) {
        free(g_st_tui_info);
        return -EINVAL;
    }
    g_report_touchid = FINGER_ID_INIT_STATE;

    return 0;
}

/*
 * New Interrupt handle implementation
 */
static void st_get_eventid(struct ts_tui_fingers *report_data)
{
    int error;
    unsigned int left_events;
    unsigned char *data = NULL;
    unsigned char *event = NULL;
    unsigned char eventId;
    event_dispatch_handler_t event_handler;
    unsigned int count;
    unsigned int size = FTS_EVENT_SIZE * (FTS_FIFO_MAX + 1);

    data = (unsigned char *)malloc(size);
    if (!data) {
        TP_LOG_ERR("data malloc failed\n");
        return;
    }

    if (memset_s(data, size, 0, size))
        goto exit;

    /*
     * to avoid reading all FIFO, we read the first event and
     * then check how many events left in the FIFO
     */
    data[0] = READ_ALL_EVENT;
    error = hisi_i2c_read(I2C_ADDR, data, FTS_EVENT_SIZE, ST_SLAVE_ADDR);
    left_events = data[LEFT_EVENTS_POS] & LEFT_EVENTS_MASK;

    if (!error && (left_events > 0) && (left_events < FTS_FIFO_MAX)) {
        data[FTS_EVENT_SIZE] = READ_ALL_EVENT;
        error = hisi_i2c_read(I2C_ADDR, &data[FTS_EVENT_SIZE], left_events * FTS_EVENT_SIZE, ST_SLAVE_ADDR);
    }

    if (error) {
        TP_LOG_ERR("%s:Error %d while reading from FIFO", __func__, error);
        goto exit;
    }

    for (count = 0; count < left_events + 1; count++) {
        event = &data[count * FTS_EVENT_SIZE];
        if (event[0] == EVT_ID_NOEVENT)
            break;

        eventId = event[0] >> OFFSET_BYTE4;
        if (eventId < NUM_EVT_ID) {
            event_handler = g_st_tui_info->event_dispatch_table[eventId];
            event_handler((event), report_data);
        }
    }

exit:
    free(data);
}

void tui_st_exit_new(void)
{
    if (g_st_tui_info) {
        if (g_st_tui_info->event_dispatch_table) {
            free(g_st_tui_info->event_dispatch_table);
            g_st_tui_info->event_dispatch_table = NULL;
        }
    }
    if (g_st_tui_info) {
        free(g_st_tui_info);
        g_st_tui_info = NULL;
    }
}

int ts_st_init(void)
{
    TP_LOG_INFO("ts_st_init\n");
    return 0;
}

#define ALIX_HEADER_SIGNATURE 0xA5
#define ALIX_HEADER_TYPE 0x3A
#define DUMMY_DATA 6
#define ST_FRAME_LEN 2864
#define ADDRESS_SAFE_SIZE 1
#define ADDRESS_SIZE 4
#define ALIX_OPCODE_READ 0xFB
#define ALIX_OPCODE_WRITE 0xFA
#define SENSE_ON_CMD_0 0x5A
#define SENSE_ON_CMD_1 0x3A
#define ALIX_FRAME_BUFFER_ADDRESS 0x20010000

int ts_st_get_frame(struct ts_tui_fingers *report_data)
{
    int ret;

    /* sense on cmd needs 2 bytes */
    unsigned char buff_temp[ST_FRAME_LEN + DUMMY_DATA] = {0};
    unsigned char buff_data[ST_FRAME_LEN + DUMMY_DATA] = {0};

    (void)report_data;
    buff_temp[0] = ALIX_OPCODE_READ;
    *(int *)(buff_temp + 1) = htonl(ALIX_FRAME_BUFFER_ADDRESS);
    ret = ts_spi_sync(ST_FRAME_LEN + DUMMY_DATA, &buff_temp[0], &buff_data[0]);
    ret = memcpy_s((void *)&g_tee_tp_buff.revbuff[0], MAX_FRAME_LEN, (void *)&buff_data[DUMMY_DATA],
        ST_FRAME_LEN);
    if (ret != 0)
        TP_LOG_ERR("%s: error reading the data frame %d\n",
            __func__, ret);

    if ((g_tee_tp_buff.revbuff[0] != ALIX_HEADER_SIGNATURE) ||
        (g_tee_tp_buff.revbuff[1] != ALIX_HEADER_TYPE))
        TP_LOG_ERR("%s: wrong header information found %02X %02X\n",
            __func__, g_tee_tp_buff.revbuff[0], g_tee_tp_buff.revbuff[1]);

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;
    return ret;
}

