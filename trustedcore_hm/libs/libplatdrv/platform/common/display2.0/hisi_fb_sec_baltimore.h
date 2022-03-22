/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display data additional definition
 * Author: Hisilicon DSS
 * Create: 2019-10-29
 */

#ifndef HISI_FB_SEC_BALTIMORE_H
#define HISI_FB_SEC_BALTIMORE_H
#include "hisi_dss.h"

#define DSS_POWER_ON_STAT (0x000cc000)

#define HISI_FB_SEC_IRQ        (399) // intr_mcu_dsi0: 367 + 32
#define HISI_FB_SEC_DSI1_IRQ   (401) // intr_mcu_dsi1: 369 + 32
#define HISI_DSS_SEC_RCH_INDEX (DSS_RCHN_D3)
#define DSS_SEC_RCH_DMA_OFFSET (DSS_RCH_D3_DMA_OFFSET)
#define MCTL_CTL_MUTEX_SEC_RCH (MCTL_CTL_MUTEX_RCH7)
#define MCTL_SEC_RCH_OV_OEN    (MCTL_RCH7_OV_OEN)
#define PERSTAT0               (0x00C)
#define MCTL_MOD_DBG (MCTL_MOD7_DBG)
#define MCTL_RCH_SECU_GATE (MCTL_RCH7_SECU_GATE)

#define MIPI_LDI_MCU_ITF_INTS    (0x0240)
#define MIPI_LDI_MCU_ITF_INT_MSK (0x0244)

#endif
