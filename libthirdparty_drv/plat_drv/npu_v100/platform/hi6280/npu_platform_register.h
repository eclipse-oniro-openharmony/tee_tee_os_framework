/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu platform register
 */
#ifndef __NPU_PLATFORM_REGISTER_H
#define __NPU_PLATFORM_REGISTER_H
#include "npu_custom_info_share.h"

#define SOC_HARDWARE_VERSION (DEVDRV_PLATFORM_LITE_ORLANDO)

#include "soc_npu_ts_sysctrl_reg_offset.h"
#include "soc_npu_tscpu_cfg_reg_offset.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_sctrl_interface.h"

#define DEVDRV_SC_TESTREG0_OFFSET \
		(SOC_TS_SYSCTRL_SC_TESTREG0_REG - SOC_TS_SYSCTRL_BASE)
#define DEVDRV_SC_TESTREG8_OFFSET \
		(SOC_TS_SYSCTRL_SC_TESTREG8_REG - SOC_TS_SYSCTRL_BASE)
#define DEVDRV_CFG_STAT0_OFFSET \
		(SOC_NPU_TSCPU_CFG_TS_CPU_STAT0_REG - SOC_TS_SYSCTRL_BASE)

#define DRV_NPU_POWER_STATUS_REG SOC_SCTRL_SCBAKDATA28_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)

#define TS_DOORBELL_BASE_ADDR        SOC_ACPU_doorbell_cfg_BASE_ADDR
#define TS_DOORBELL_BASE_ADDR_SIZE   0x80000 /* 512KB */

#define TS_SRAM_BASE_ADDR            SOC_ACPU_SRAM_normal_BASE_ADDR
#define TS_SRAM_BASE_ADDR_SIZE       0x10000 /* 64KB */

#define L2BUF_BASE_BASE_ADDR         SOC_ACPU_L2BUF_BASE_ADDR
#define L2BUF_BASE_BASE_ADDR_SIZE    0x80000 /* size: 512KB */

#endif
