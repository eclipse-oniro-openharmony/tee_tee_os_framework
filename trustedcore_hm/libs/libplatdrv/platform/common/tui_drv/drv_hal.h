/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tui driver hal interface to invoke the hardware platform
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-03-04
 */
#ifndef TASK_TUI_DRV_HAL_H
#define TASK_TUI_DRV_HAL_H

#include <stdint.h>
#include "tui_drv.h"

#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
#include <display_tui_hal.h>
#else
#include <hisi_disp.h>
#endif


#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
int32_t tui_get_disp_info(struct panel_info *info);
#else
int32_t tui_get_disp_info(struct hisi_panel_info *info);
#endif
bool set_fb_mem_mode(struct mem_cfg *fb_cfg, enum sec_mode mode);
bool set_fb_drv_mode(struct fb_cfg *cfg, enum sec_mode mode);
bool set_tp_drv_mode(struct tp_cfg *cfg, enum sec_mode mode);
bool set_ttf_mode(struct ttf_cfg *ttf, enum sec_mode mode);
void set_tp_slide_mode(bool slide);
void set_thp_start_flag(bool mode);
#endif /* TASK_TUI_DRV_HAL_H */