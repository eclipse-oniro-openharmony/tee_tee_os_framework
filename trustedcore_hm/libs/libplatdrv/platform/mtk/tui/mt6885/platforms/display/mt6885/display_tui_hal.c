/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include "display_tui_hal.h"
#include "tee_log.h"
#include "display_tui.h"
#include "mem_ops.h"

int32_t fb_cfg_sec(int32_t value)
{
    int32_t ret;

    if (value == 1) {
        ret = disp_tui_init();
        if (ret != 0) {
            tloge("display int tui fail 0x%x", ret);
            return ret;
        }
        ret = disp_tui_enter();
        if (ret != 0) {
            tloge("disp_tui_enter fail 0x%x", ret);
            return ret;
        }
    } else if (value == 0) {
        ret = disp_tui_leave();
        if (ret != 0) {
            tloge("disp_tui_leave fail 0x%x", ret);
            return ret;
        }
    } else {
        tloge("error value type");
        return -1;
    }
    return 0;
}

int32_t pan_display_sec(dss_layer_t *layer)
{
    int32_t ret = 0;
    if (layer == NULL) {
        tloge("layer is null");
        return -1;
    }

    ret = disp_tui_pan_display(layer);
    if (ret != 0) {
        tloge("disp_tui_pan_display fail 0x%x", ret);
        return ret;
    }

    tloge("pan_display_sec end");
    return 0;
}
int32_t get_disp_info(struct panel_info *pinfo)
{
    if (pinfo == NULL)
        return -1;

    pinfo->xres = get_x_res();
    pinfo->yres = get_y_res();
    return 0;
}

int32_t wait_vactive_flag(void)
{
    while(get_disp_tui_set_disp_flag() == 0) {
        ;
    }
    set_tui_disp_flag(0);

    return 0;
}

int32_t wait_release_flag(void)
{
    while (get_disp_tui_get_free_flag() == 0) {
        ;
    }

    set_tui_free_flag(0);

    return 0;
}
