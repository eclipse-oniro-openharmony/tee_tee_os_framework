/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: TUI tp platform common driver
 * Author: chenpuwang
 * Create: 2020-10-10
 */
#ifndef _HISI_TUI_TOUCHSCREEN_
#define _HISI_TUI_TOUCHSCREEN_

#include <stdbool.h>
#include <stdint.h>
#include <malloc.h>
#include <drv_mem.h>
#include <mem_ops.h>
#include <mem_ops_ext.h>
#include <sre_hwi.h>
#include <sre_hwi_ipc.h>
#include <tee_log.h>
#include <dlist.h>
#include <libhwsecurec/securec.h>
#include "tui_drv_types.h"
#include "tui_timer.h"

#define NO_ERR 0
#define ERROR (-1)

#define TP_HWI_NUM 140

#define TS_TUI_MAX_FINGER 10
#define TS_FINGER_RELEASE (1 << 5)
#define TS_FINGER_PRESS (1 << 6)

#define IRQ_TYPE_TP 1 /* irq from touchscreen */
#define TYPE_TOUCH 64
#define TYPE_RELEASE 32
#define ACCEPT_NUM 3

#define THP_PROJECT_ID_LEN 10
#define MAX_FRAME_LEN 4096

#define TS_GET_FRAME 0x1
#define TS_SPI_SYNC 0x2
#define TS_IRQ_CTL 0x3
#define TS_GET_PRO_ID 0x4
#define TS_SYNC_FRAME 0x5

#define TP_CONFIG_RESEVED_DATA_LEN 10

/* struct fingers */
struct ts_tui_finger {
    int32_t status;
    int32_t x;
    int32_t y;
    int32_t area;
    int32_t pressure;
    int32_t orientation;
    int32_t major;
    int32_t minor;
    int32_t event;
    uint32_t cur_pid;
};

struct ts_tui_fingers {
    struct ts_tui_finger fingers[TS_TUI_MAX_FINGER];
    int32_t cur_finger_number;
    uint32_t gesture_wakeup_value;
    uint32_t special_button_key;
    uint32_t special_button_flag;
};


struct ts_frame_data {
    uint32_t size;
    char buf[MAX_FRAME_LEN];
};

#define MAX_REG_BUF_SIZE (MAX_FRAME_LEN / 2)
struct ts_reg_data {
    uint32_t size;
    unsigned char txbuf[MAX_REG_BUF_SIZE];
    unsigned char rxbuf[MAX_REG_BUF_SIZE];
};

struct ts_info {
    union __ts_ioctl_data {
        struct ts_frame_data ts_frame_info;
        struct ts_reg_data reg_data;
        char project_id[THP_PROJECT_ID_LEN + 1];
    } ts_ioctl_data;
    unsigned char reserved;
};

struct tee_thp_frame_buff {
    unsigned char revbuff[MAX_FRAME_LEN];
    unsigned char flag; /* store 1 send set 0 */
};

struct tp_info {
    struct ts_tui_finger finger_data;
    struct dlist_node list;
};

bool init_tp_data(uint64_t tp_info_phy);
int32_t tui_tp_exit(void);
bool tui_tp_driver_init(void *cfg);
int32_t tui_get_chip_type(void);
void display_state_notify(bool mode);
struct tee_thp_frame_buff *get_tp_frame_buff(void);
int32_t tui_tp_get_frame_max_len(void);
void tui_tp_set_frame_count(int32_t count);
int32_t tui_tp_get_frame_count(void);
int32_t ts_get_frame(void);
int32_t ts_ioctl(uint32_t cmd, void *arg);

#define TP_TUI_NEW_IRQ_SUPPORT 1
#define TP_TUI_NEW_IRQ_MASK 0x1

#endif
