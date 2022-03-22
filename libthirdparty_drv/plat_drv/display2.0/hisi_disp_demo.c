/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display interfaces with secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_disp.h"

/* dss secure mode init
 * input: sec_value,
 *        if true, enter into secure pay mode
 *        if false, exit secure pay mode
 * return: 0, success
 *       -1, failed
 */
int hisi_fb_cfg_sec(int sec_value)
{
	return 0;
}

/*
 * receive one frame data information
 *
 * input: rect, display region and data format(bpp)
 *       display_addr, display buffer base address etc.
 *
 * return: 0, success
 *       -1, failed
 */
int hisi_pan_display_sec(dss_layer_t *layer)
{
	return 0;
}

int hisi_wait_vactive_flag(void)
{
	return 0;
}

int hisi_wait_release_flag(void)
{
	return 0;
}

int hisi_get_disp_info(struct hisi_panel_info *pinfo)
{
	return 0;
}
