/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
* Description: isp interface
* Author: z00367550
* Create: 2019-9-26
*/

#ifndef _KIRIN_ISP_HISP_H_
#define _KIRIN_ISP_HISP_H_

#include "global_ddr_map.h"
#include "soc_acpu_baseaddr_interface.h"

#define CRG_BASE                        (SOC_ACPU_PERI_CRG_BASE_ADDR)
#define ISP_BASE                        (SOC_ACPU_ISP_Core_CFG_BASE_ADDR)
#define MEDIA_CRG_BASE_ADDR             (SOC_ACPU_MEDIA1_CRG_BASE_ADDR)
#define ISP_SUB_CTRL                    (SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR)

#define MEDIA1_CRGPERDIS0               (MEDIA_CRG_BASE_ADDR + 0x004U)
#define MEDIA1_PERRSTDIS0               (MEDIA_CRG_BASE_ADDR + 0x034U)
#define MEDIA1_CRGCLKDIV9               (MEDIA_CRG_BASE_ADDR + 0x084U)
#define MEDIA1_ISP_CPU_STATE0           (MEDIA_CRG_BASE_ADDR + 0x150U)
#define MEDIA1_ISP_CPU_CLKEN            (MEDIA_CRG_BASE_ADDR + 0x140U)
#define MEDIA1_ISP_CPU_RSTEN            (MEDIA_CRG_BASE_ADDR + 0x144U)
#define MEDIA1_PERRSTEN_ISP_SEC         (MEDIA_CRG_BASE_ADDR + 0x800U)
#define MEDIA1_PERRSTDIS_ISP_SEC        (MEDIA_CRG_BASE_ADDR + 0x804U)
#define MEDIA1_PERRSTSTAT_ISP_SEC       (MEDIA_CRG_BASE_ADDR + 0x808U)
#define MEDIA1_ISPCPU_CTRL0_SEC         (MEDIA_CRG_BASE_ADDR + 0x810U)
#define CRG_PERRSTSTAT5                 (CRG_BASE + 0x0A4U)

#define ACTRLISO_EN_GROUP1_PERI         (ACTRL_BASE + 0x004U)
#define ACTRLMTCMOS_EN_GROUP1_PERI      (ACTRL_BASE + 0x014U)
#define ACTRLBISR_REPAIR_ACK_STATUS0    (ACTRL_BASE + 0x058U)

#define PCTRLPERI_CTRL102               (PCTRL_BASE + 0x028U)

#define ISP_ARC_CTRL_0                  (ISP_SUB_CTRL + 0x40)
#define ISP_ARC_CTRL_8                  (ISP_SUB_CTRL + 0x118)
#define ISP_ARC_CTRL_9                  (ISP_SUB_CTRL + 0x120)
#define ISP_ARC_CTRL_10                 (ISP_SUB_CTRL + 0x12C)
#define ISP_ARC_CTRL_11                 (ISP_SUB_CTRL + 0x130)
#define ISP_ARC_CTRL_12                 (ISP_SUB_CTRL + 0x134)
#define ISP_ARC_SUB_CTRL10              (ISP_SUB_CTRL + 0x240U)
#define ISP_CORE_CTRL_S                 (ISP_SUB_CTRL + 0x800U)
#define ISP_SUB_CTRL_S                  (ISP_SUB_CTRL + 0x804U)
#define ISP_CPU_SMMU_CTRL_S             (ISP_SUB_CTRL + 0x808U)
#define ISP_SUBCTRL_CANARY_ADDR         (ISP_SUB_CTRL + 0x6FC)

#define ISPSS_CTRL                      (ISP_BASE + 0x20000U)
#define ISPSS_MODULE_CGR_HARDEN_SET     (ISPSS_CTRL + 0x368U)
#define ISPSS_MODULE_CGR_HARDEN_CLEAR   (ISPSS_CTRL + 0x36CU)
#define ISPSS_MODULE_RESET_HARDEN_SET   (ISPSS_CTRL + 0x378U)
#define ISPSS_MODULE_RESET_HARDEN_CLEAR (ISPSS_CTRL + 0x37CU)
#define ISPSS_MODULE_CGR_TOP            (ISPSS_CTRL + 0x030U)

#define MEDIA1_TCU_BASE                 (SOC_ACPU_MEDIA1_TCU_BASE_ADDR)
#define MEDIA1_TCU_SCR                  (SOC_ACPU_MEDIA1_TCU_BASE_ADDR + 0x8E18U)
#define MEDIA1_TCU_LP_REQ               (SOC_ACPU_MEDIA1_TCU_BASE_ADDR + 0x30000U)
#define MEDIA1_TCU_LP_ACK               (SOC_ACPU_MEDIA1_TCU_BASE_ADDR + 0x30004U)
#define MEDIA1_TCU_CTRL_SCR             (SOC_ACPU_MEDIA1_TCU_BASE_ADDR + 0x30090U)

#define ISP_ARC_SMMU_TBU_CR             (SOC_ACPU_TBU_ISP_ARC_CFG_BASE_ADDR + 0x0U)
#define ISP_ARC_SMMU_TBU_CRACK          (SOC_ACPU_TBU_ISP_ARC_CFG_BASE_ADDR + 0x4U)
#define ISP_ARC_SMMU_TBU_SCR            (SOC_ACPU_TBU_ISP_ARC_CFG_BASE_ADDR + 0x1000U)

#define ISP_SUBSYS1_REPAIR_ACK_STATUS0  (1 << 10)
#define ISP_SUBSYS2_REPAIR_ACK_STATUS0  (1 << 11)

#define ISP_MODULE_CRG_MASK             (0x1)

#define ISP_CPU_MID_VALUE               0x47
#define IP_RST_ISP                      1
#define IP_RST_MEDIA                    (3 << 17)

#define ISP_ARC_REMAP_ENABLE            (1 << 31)
#define ISP_CPU1_ARC_RUN_ACK            (1 << 15)
#define ISP_CPU0_ARC_RUN_ACK            (1 << 13)
#define ISP_CPU_ARC_RUN_ACK             (ISP_CPU0_ARC_RUN_ACK | ISP_CPU1_ARC_RUN_ACK)
#define ISP_CPU1_ARC_RUN_REQ            (1 << 5)
#define ISP_CPU0_ARC_RUN_REQ            (1 << 3)
#define ISP_CPU_ARC_RUN_REQ             (ISP_CPU0_ARC_RUN_REQ | ISP_CPU1_ARC_RUN_REQ)
#define ISP_CPU_ARC_MEM_CTRLS           0x5858
#define ISP_CPU_INTVBASE_IN             10
#define ISPA7_REMAP_HADDR_OFFSET        32

#define NOTUSE_POLL_STAT                0
#define FINAL_STAT                      0x4
#define USE_FINAL                       (1 << 31)
#define POLL_0_BIT                      (1 << 30)
#define POLL_MINUS                      (1 << 29)
#define ISP_CPU0_ARC_RUN_REQ            (1 << 3)

#define SMMU_TCU_QREQN_DN               (1 << 1)
#define SMMU_TCU_QREQN_CG               1
#define SMMU_TCU_QACCEPTN_PD            (1 << 4)
#define SMMU_TCU_QACCEPTN_CG            1
#define SMMU_TCU_NS_INIT                (1 << 3)
#define SMMU_TCU_NS_UARCH               1
#define SMMU_TBU_EN_REQ                 1
#define SMMU_TBU_EN_ACK                 1
#define SMMU_TBU_CONNECTED              (1 << 1)

#define MAX_RESULT_LENGTH               8

/* ISP SUBCTRL */
#define ISP_SUBCTRL_CSSYS_DBGEN         1
#define ISP_SUBCTRL_CSSYS_NIDEN         (1 << 1)
#define ISP_SUBCTRL_CFGNMFI             0x3
#define ISP_SUBCTRL_NCPUHALT            (0x3 << 29)
#define ISP_SUBCTRL_DBG_SPRAM_MEM_CTRL  0x00005858
#define MEDIA_ISPCPU_CTRL0_SEC          0x00161600

/* smmu */
#define ISP_ARC_SMMU_TBU                (SOC_ACPU_TBU_ISP_ARC_CFG_BASE_ADDR)
#define ISP_ARC_SEC_ADPT                (SOC_ACPU_TBU_ISP_ARC_SEC_ADPT_BASE_ADDR)
#define ISP_SRT_SMMU_TBU                (SOC_ACPU_ISP_Core_CFG_BASE_ADDR + 0x00240000)
#define ISP_RT_SMMU_TBU                 (SOC_ACPU_ISP_Core_CFG_BASE_ADDR + 0x00250000)
#define ISP_RYYB_SMMU_TBU               (SOC_ACPU_ISP_Core_CFG_BASE_ADDR + 0x00260000)

#define SMMUV3_TCU_CTRL_REG_OFFSET                  0x30000
#define SMMUV3_TCU_CTRL_REG_SMMU_TCU_LP_REQ_REG     0x0  /* SMMU TCU low-power request register. */
#define SMMUV3_TCU_CTRL_REG_SMMU_TCU_LP_ACK_REG     0x4  /* SMMU TCU low-power acknowledge register. */
#define SMMUV3_TCU_REG_SMMU_TCU_NODE_STATUS_0_REG   0x9400  /* TCU Node Status register */
#define SMMUV3_TCU_CTRL_REG_TCU_QREQN_CG_OFFSET     0
#define SMMUV3_TCU_CTRL_REG_TCU_QACCEPTN_CG_OFFSET  0
#define SMMUV3_TCU_CTRL_REG_TCU_QREQN_PD_OFFSET     1
#define SMMUV3_TCU_CTRL_REG_TCU_QACCEPTN_PD_OFFSET  4
#define SMMUV3_TBU_REG_SMMU_TBU_SCR_REG             0x1000 /* TBU Secure Control Register */
#define SMMUV3_TBU_REG_SMMU_TBU_CR_REG              0x0    /* TBU Control Register */
#define SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG           0x4    /* TBU Control Acknowledge Register */
#define SMMUV3_TBU_REG_TBU_EN_REQ_OFFSET            0
#define SMMUV3_TBU_REG_TBU_EN_ACK_OFFSET            0
#define SMMUV3_TBU_REG_SWID_CFG_NS                  0x4
#define SMMUV3_TBU_REG_SWID_CFG_S                   0x800

#define SMMUV3_DELAY_TIME                           1000
#define SMMUV3_DELAY_TIMEOUT                        100
#define SMMUV3_SID_OFFSET                           4

#define SMMUV3_SSID_MAX                             64
#define ISP_SMMUV3_SID                              0x3

#define CGR_SRT                                     0
#define CGR_RT                                      1
#define CGR_CAP                                     2

/* SEC MEM INFO */
#define SEC_ISP_BIN_SIZE               HISI_RESERVED_SEC_CAMERA_PHYMEM_SIZE
#define SEC_ISP_IMG_BASE_ADDR          HISI_RESERVED_SEC_CAMERA_PHYMEM_BASE


#define SEC_ISP_IMG_TEXT_BASE_ADDR     (SEC_ISP_IMG_BASE_ADDR)
#define SEC_ISP_IMG_TEXT_SIZE          0x00600000
#define SEC_ISP_IMG_DATA_BASE_ADDR     (SEC_ISP_IMG_TEXT_BASE_ADDR + SEC_ISP_IMG_TEXT_SIZE)
#define SEC_ISP_IMG_DATA_SIZE          (SEC_ISP_BIN_SIZE - SEC_ISP_IMG_TEXT_SIZE)
#define BBOX_MEM_BASE_ADDR             0x2FB00000
#define BBOX_MEM_BASE_ADDR_SIZE        0x860000

#define SECISP_BOOTWARE_SIZE    0x10000
#define SEC_CMA_IMAGE_SIZE             (SEC_ISP_BIN_SIZE)

#define ISP_DEBUG_ENABLE               (1 << 0)
#define ISP_WARRING_ENABLE             (1 << 1)
#define ISP_INFO_MASK                  (1 << 2)
#define ISP_ERR_MASK                   (1 << 3)

#ifdef ISP_CHIP_ES
#define TEXT_BASE                      0x00A00000
#define ISP_TEXT_SIZE                  0x00600000
#endif
extern void uart_printf_func(const char *fmt, ...);

#define ISP_PRINT_FLAG \
    (ISP_ERR_MASK | ISP_WARRING_ENABLE)

#define ISP_ERR(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_ERR_MASK) { \
            uart_printf_func("[secisp][E]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_WARN(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_WARRING_ENABLE) {  \
            uart_printf_func("[secisp][W]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_INFO(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_INFO_MASK) {   \
            uart_printf_func("[secisp][I]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

#define ISP_DEBUG(fmt, args...) \
    do { \
        if (ISP_PRINT_FLAG & ISP_DEBUG_ENABLE) { \
            uart_printf_func("[secisp][D]<%s,%d> " fmt, __func__, __LINE__, ##args); \
        } \
    } while (0)

enum {
	SECISP_SUCCESS = 0,
	SECISP_FAIL,
	SECISP_BAD_PARA = 100,
	SECISP_TIMEOUT,
	SECISP_INVAILD_ADDR_MAP,
	SECISP_ERR_MAX,
};

#endif /* _KIRIN_ISP_HISP_H_ */

