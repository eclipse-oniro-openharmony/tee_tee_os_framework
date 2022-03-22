/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display data additional definition
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_FB_SEC_KIRIN980_H
#define HISI_FB_SEC_KIRIN980_H
#include "hisi_dss.h"

#define DSS_POWER_ON_STAT (0x000dc000)

#define HISI_FB_SEC_IRQ        (280) // dss-pdp for mcu 248 + 32
#define HISI_DSS_SEC_RCH_INDEX (DSS_RCHN_V0) // base index
#define DSS_SEC_RCH_DMA_OFFSET (DSS_RCH_VG0_DMA_OFFSET) // no need
#define MCTL_CTL_MUTEX_SEC_RCH (MCTL_CTL_MUTEX_RCH2)
#define MCTL_SEC_RCH_OV_OEN    (MCTL_RCH2_OV_OEN)
#define PERSTAT0               (0x00C)
#define MCTL_MOD_DBG (MCTL_MOD2_DBG)
#define MCTL_RCH_SECU_GATE (MCTL_RCH2_SECU_GATE)

#endif
