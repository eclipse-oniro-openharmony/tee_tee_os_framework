/* Copyright (c) 2013-2014, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#ifndef HISI_OVERLAY_UTILS_KIRIN710_H
#define HISI_OVERLAY_UTILS_KIRIN710_H
#include "hisi_dss.h"

#define DSS_POWER_ON_STAT       (0x000dc000)

#define HISI_FB_SEC_IRQ         (280) // dss-pdp for mcu 248 + 32
#define HISI_DSS_SEC_RCH_INDEX  (DSS_RCHN_V1)
#define DSS_SEC_RCH_DMA_OFFSET  (DSS_RCH_VG1_DMA_OFFSET)
#define MCTL_CTL_MUTEX_SEC_RCH  (MCTL_CTL_MUTEX_RCH4)
#define MCTL_SEC_RCH_OV_OEN     (MCTL_RCH4_OV_OEN)

#define DSS_CHN_MAX_DEFINE (DSS_COPYBIT_MAX)

// use the way of query vsync_reg replace for vactive_start or frame_end.
#define CONFIG_DSS_LDI_QVSYNC_USED (0)

// use vsync signal int replace for vactive_start or frame_end int.
// when CONFIG_DSS_LDI_QVSYNC_USED was defined, CONFIG_DSS_LDI_VSYNC_USED is useless.
#define CONFIG_DSS_LDI_VSYNC_USED (0)

#endif  /* HISI_OVERLAY_UTILS_KIRIN710_H */
