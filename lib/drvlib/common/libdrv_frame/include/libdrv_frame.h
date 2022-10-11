/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: drv frame function declarement
 * Create: 2020-04-15
 */
#ifndef LIBDRV_FRAME_DRV_FRAME_H
#define LIBDRV_FRAME_DRV_FRAME_H

#include <cs.h>
#include <stdbool.h>

typedef int32_t (*drv_frame_init_t)(void);

struct drv_frame_t {
    const char *name;
    bool is_irq_triggered;
    drv_frame_init_t init;
};

int32_t drv_framework_init(const struct drv_frame_t *drv_frame);
int32_t hm_register_drv_framework(const struct drv_frame_t *drv_frame, cref_t *ch, bool new_frame);
cref_t get_sysctrl_hdlr(void);
#endif
