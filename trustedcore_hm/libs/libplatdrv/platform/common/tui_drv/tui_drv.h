/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: syscall main message procedure for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-2-29
 */
#ifndef TASK_TUI_DRV_H
#define TASK_TUI_DRV_H

#include <stdint.h>

#include "mem_cfg.h"

struct tui_page_info_k {
    uint64_t phys_addr;
    uint32_t npages;
};

struct tui_ion_sglist_k {
    uint64_t sglist_size;
    uint64_t ion_size;
    uint64_t ion_id;
    uint64_t info_length; /* page_info number of tui */
    struct tui_page_info_k page_info[0];
};

struct tui_sglist_page {
    struct tui_ion_sglist_k sglist;
    struct tui_page_info_k page;
};

enum init_step {
    INIT_NONE,
    INIT_FB_MEM,
    INIT_FB_DRV,
    INIT_TP_DRV,
    INIT_TTF_MEM,
    INIT_TIMER,
    INIT_RELCB,
    INIT_OVER,
};

struct fb_cfg {
    struct mem_cfg cfg;
    enum sec_mode drv_mode;
};

struct ttf_cfg {
    struct mem_cfg cfg;
    enum data_setted set;
};

struct tp_cfg {
    uint64_t tp_info_phy;
    int32_t type;
    enum sec_mode drv_mode;
    uint32_t drv_pid;
    uint32_t caller_pid;
};

struct drv_state {
    struct fb_cfg fb_cfg;
    struct tp_cfg tp_cfg;
    struct ttf_cfg ttf;

    struct tui_panel_info_k panel;
    enum init_step step;
};

#endif /* TASK_TUI_DRV_H */