/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display register address definition
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_FB_SEC_H
#define HISI_FB_SEC_H

#include "hisi_disp.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_dss_interface.h"

#if defined(CONFIG_DSS_TYPE_KIRIN970)
#include "hisi_fb_sec_kirin970.h"

#elif defined(CONFIG_DSS_TYPE_KIRIN980)
#include "hisi_fb_sec_kirin980.h"

#elif defined(CONFIG_DSS_TYPE_KIRIN990)
#include "hisi_fb_sec_kirin990.h"

#elif defined(CONFIG_DSS_TYPE_ORLANDO)
#include "hisi_fb_sec_orlando.h"

#elif defined(CONFIG_DSS_TYPE_KIRIN710)
#include "hisi_fb_sec_kirin710.h"

#elif defined(CONFIG_DSS_TYPE_BALTIMORE)
#include "hisi_fb_sec_baltimore.h"

#elif defined(CONFIG_DSS_TYPE_DENVER) || defined(CONFIG_DSS_TYPE_LAGUNA) || \
	defined(CONFIG_DSS_TYPE_BURBANK)
#include "hisi_fb_sec_denver.h"

#endif

struct hisi_disp_info {
	uint32_t   res_type;
	uint32_t   xres;
	uint32_t   yres;
	uint32_t   density;
	uint8_t    bpp;
	uint32_t   tp_color;
	uint32_t   bl_ic_ctrl_mode;
};

int device_probe(struct hisifb_data_type *hisifd);

#endif
