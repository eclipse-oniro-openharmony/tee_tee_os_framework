/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#ifndef HISI_FB_SEC_H
#define HISI_FB_SEC_H

#if defined (CONFIG_DSS_TYPE_HI365X)
#include "hisi_overlay_utils_hi365x.h"
#include "hisi_dss_regs.h"

#elif defined (CONFIG_DSS_TYPE_HI625X)
#include "hisi_overlay_utils_hi625x.h"
#include "hisi_dss_regs.h"

#elif defined (CONFIG_DSS_TYPE_HI366X)
#include "hisi_overlay_utils_hi366x.h"
#include "hisi_dss_regs_hi366x.h"

#elif defined (CONFIG_DSS_TYPE_KIRIN970)
#include "hisi_overlay_utils_kirin970.h"
#include "hisi_dss_regs_kirin970.h"

#elif defined (CONFIG_DSS_TYPE_KIRIN980)
#include "hisi_overlay_utils_kirin980.h"
#include "hisi_dss_regs_kirin980.h"

#elif defined (CONFIG_DSS_TYPE_KIRIN990)
#include "hisi_overlay_utils_kirin990.h"
#include "hisi_dss_regs_kirin990.h"

#elif defined (CONFIG_DSS_TYPE_ORLANDO)
#include "hisi_overlay_utils_orlando.h"
#include "hisi_dss_regs_orlando.h"

#elif defined (CONFIG_DSS_TYPE_KIRIN710)
#include "hisi_overlay_utils_kirin710.h"
#include "hisi_dss_regs_kirin710.h"

#elif defined (CONFIG_DSS_TYPE_BALTIMORE)
#include "hisi_overlay_utils_baltimore.h"
#include "hisi_dss_regs_baltimore.h"
#endif

#define TIME_OUT            (200)

#define outp32(addr, val)   writel(val, addr)
#define inp32(addr)         readl(addr)

enum {
	SEC_PAY_DISABLE = 0,
	SEC_PAY_ENABLE = 1,
};

enum {
	DSS_MIPI_DSI_VIDEO_MODE = 0,
	DSS_MIPI_DSI_CMD_MODE   = 1,
};

enum {
	NON_SECURE_MODE = 0,
	SECURE_MODE = 1,
	PROTECTED_MODE = 2,
};

extern UINT32 SRE_SwMsleep(UINT32 uwMsecs);
extern void uart_printf_func(const char *fmt, ...);
extern unsigned int hisi_fb_msg_level;
#define HISI_FB_ERR(msg, ...) \
	do { if (hisi_fb_msg_level >= 1)  \
		uart_printf_func("[hisifb]%s: "msg, __func__, ## __VA_ARGS__); } while (0)

#define HISI_FB_INFO(msg, ...) \
	do { if (hisi_fb_msg_level >= 3)  \
		uart_printf_func("[hisifb]%s: "msg, __func__, ## __VA_ARGS__); } while (0)

#define HISI_FB_DEBUG(msg, ...) \
	do { if (hisi_fb_msg_level >= 7)  \
		uart_printf_func("[hisifb]%s: "msg, __func__, ## __VA_ARGS__); } while (0)

#define HISI_FB_PRINTF(msg, ...) \
	do { if (hisi_fb_msg_level >= 1)  \
		uart_printf_func(""msg, ## __VA_ARGS__); } while (0)

extern uint32_t g_dss_module_ovl_base[DSS_MCTL_IDX_MAX][MODULE_OVL_MAX];
extern uint32_t g_dss_module_base[DSS_CHN_MAX_DEFINE][MODULE_CHN_MAX];

typedef struct hisi_disp_info {
	uint32_t   res_type;
	uint32_t   xres;
	uint32_t   yres;
	uint32_t   density;
	uint8_t    bpp;
	uint32_t   tp_color;
	uint32_t   bl_ic_ctrl_mode;
} hisi_disp_info_t;

extern void dump_dss_reg_info(struct hisifb_data_type *hisifd);
extern int device_probe(struct hisifb_data_type *hisifd);
extern void single_frame_update(struct hisifb_data_type *hisifd);
extern int hisi_fb_irq_handle(uint32_t ptr);
extern int hisi_dss_sec_pay_config(struct hisifb_data_type *hisifb, int value);
extern int do_pan_display_config(struct hisifb_data_type *hisifd, dss_layer_t *layer);
extern int hisi_vactive0_start_config(struct hisifb_data_type *hisifd);
extern int hisi_frame_end_config(struct hisifb_data_type *hisifd);
extern void hisi_dss_mcu_interrupt_mask(struct hisifb_data_type *hisifd);
extern void hisi_dss_mcu_interrupt_unmask(struct hisifb_data_type *hisifd);
extern int hisi_fb_irq_handle(uint32_t ptr);
extern int hisi_dss_mif_config(struct hisifb_data_type *hisifd, uint32_t chn_idx, int secure);
extern int hisi_dss_smmu_config(struct hisifb_data_type *hisifd, uint32_t chn_idx, int secure);
extern int hisi_exit_secu_pay(struct hisifb_data_type *hisifd);
extern void hisi_dss_ovl_layer_config(struct hisifb_data_type *hisifd, dss_layer_t *layer);
#endif
