/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: types defined for communication between app and driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-03-31
 */
#ifndef TASK_TUI_DRV_TYPES_H
#define TASK_TUI_DRV_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#define TASK_PLAT_DRV "platdrv"

#define tui_logt(fmt, ...) uart_printf_func("%d:" fmt, __LINE__, ##__VA_ARGS__)

struct tui_panel_info_k {
    uint32_t type;
    uint32_t xres;
    uint32_t yres;
    uint32_t width;  /* physical width cm */
    uint32_t height; /* physical height cm */
    uint32_t notch;
    uint32_t bpp;
    uint32_t fps;
    uint32_t orientation;
    uint32_t fold_state;
    uint32_t display_state;
};

#define TYPE_TOUCH   64
#define TYPE_RELEASE 32
struct event_node {
    int32_t status;
    int32_t x;
    int32_t y;
};

struct tui_config {
    uint64_t phy_addr;    /* in */
    uint32_t phy_size;    /* in */
    uint32_t vm_addr;     /* out */
    uint32_t vm_size;     /* out */
    uint64_t tp_info_phy; /* in */
    uint32_t npages;      /* in */
    uint64_t info_length; /* in */
};

enum sec_mode {
    SECURE_DISABLE,
    SECURE_ENABLE,
};

enum data_setted {
    DATA_UNSET,
    DATA_SET,
};

struct map_node {
    uint32_t vm_addr;
    int32_t file_size;
};

enum tui_drv_msg {
    TUI_DRV_MSG_BASE = 0xA0000000,
    TUI_DRV_MSG_TP_EVENT,
    TUI_DRV_MSG_TIMER_CURSOR,
    TUI_DRV_MSG_TIMER_TIMEOUT,
    TUI_DRV_MSG_MAX
};

#define MAKE64(high, low) ((((uint64_t)(high)) << 32) | (uint32_t)(low))
#define HIGH32(value)     ((uint32_t)((uint64_t)(value) >> 32))
#define LOW32(value)      ((uint32_t)(value))
#define HIGH8(value)      ((uint8_t)((uint16_t)(value) >> 8))
#define LOW8(value)       ((uint8_t)(value))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
int32_t get_fold_screen(struct tui_panel_info_k *panel);

#endif /* TASK_TUI_DRV_TYPES_H */
