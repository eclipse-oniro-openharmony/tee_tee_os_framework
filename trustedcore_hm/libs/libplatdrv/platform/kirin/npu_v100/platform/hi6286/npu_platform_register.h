/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:about npu platform register
 */
#ifndef __NPU_PLATFORM_REGISTER_H
#define __NPU_PLATFORM_REGISTER_H
#include "npu_custom_info_share.h"

#include "soc_npu_ts_sysctrl_reg_offset.h"
#include "soc_npu_tscpu_cfg_reg_offset.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_sctrl_interface.h"
#include "soc_smmuv3_interface.h"
#include "soc_npu_sctrl_interface.h"

#define SOC_HARDWARE_VERSION (DEVDRV_PLATFORM_LITE_BURBANK)

#define DEVDRV_SC_TESTREG0_OFFSET \
		(SOC_TS_SYSCTRL_SC_TESTREG0_REG - SOC_TS_SYSCTRL_BASE)
#define DEVDRV_SC_TESTREG8_OFFSET \
		(SOC_TS_SYSCTRL_SC_TESTREG8_REG - SOC_TS_SYSCTRL_BASE)
#define DEVDRV_CFG_STAT0_OFFSET \
		(SOC_NPU_TSCPU_CFG_TS_CPU_STAT0_REG - SOC_TS_SYSCTRL_BASE)

#define DRV_NPU_POWER_STATUS_REG \
	SOC_SCTRL_SCBAKDATA28_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)

#define TS_DOORBELL_BASE_ADDR                                 (SOC_ACPU_doorbell_cfg_BASE_ADDR)
#define TS_DOORBELL_BASE_ADDR_SIZE                            0x80000 /* 512KB */
#define TS_SRAM_BASE_ADDR                                     (SOC_ACPU_SRAM_normal_BASE_ADDR)
#define TS_SRAM_BASE_ADDR_SIZE                                0x10000 /* 64KB */
#define L2BUF_BASE_BASE_ADDR                                  0xE4800000
/* no l2, one track need define, l2 do not use in sec runtime */
#define L2BUF_BASE_BASE_ADDR_SIZE                             0x0
#define SMMU_AICORE_TBU_CTRL_BASE_ADDR                        (SOC_ACPU_AIC_TBU_BASE_ADDR + 0x10000)
#define SMMU_SYSDMA_TBU_CTRL_BASE_ADDR                        (SOC_ACPU_SYSDMA_TBU_BASE_ADDR + 0x10000)
#define SOC_SMMUV3_SMMU_TBU_SWID_CFG(base, m)                 ((base) + (0x100UL + (m) * 4UL))

#define SOC_IOMCU_SCTRL_NPU_BASE_ADDR                         (SOC_ACPU_npu_sysctrl_BASE_ADDR)

#define NPU_AIC_TBU_MAX_TOK_TRANS                             (0x18 << 8)
#define NPU_SYSDMA_TBU_MAX_TOK_TRANS                          (0x18 << 8)
#define NPU_TBU_MAX_TOK_TRANS_MASK                            0xFF00

#define NPU_TBU_EN_REQ                                        0x1
#define NPU_TBU_DISABLE_REQ                                   0x0
#define NPU_TBU_EN_REQ_MASK                                   0x1

#define NPU_AIC_TBU_PREFSLOT_FULL_LEVEL                       (0x18 << 24)
#define NPU_AIC_TBU_PREFSLOT_FULL_LEVEL_MASK                  0x3F000000
#define NPU_TBU_PREF_ENABLE                                   0x80000000
#define NPU_TBU_PREF_ENABLE_MASK                              0x80000000

#define NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL                     (0x18 << 16)
#define NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL_MASK                0x3F0000

#define NPU_SID_MASK                                          0x3FFFF
#define SMMU_TBU_EN_ACK_MASK                                  0x1
#define SMMU_TBU_EN_ACK_VAL                                   0x1
#define SMMU_TBU_CONNECTED_STATE_MASK                         0x2
#define SMMU_TBU_CONNECTED_VAL                                0x2
#define SMMU_TBU_DISCONNECTED_VAL                             0x0

#define NPU_SWID_MAX_CNT                                      18

#endif
