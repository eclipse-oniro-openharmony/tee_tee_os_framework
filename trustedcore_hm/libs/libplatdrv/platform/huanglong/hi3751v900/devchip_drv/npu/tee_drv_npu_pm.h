/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hisi npu pm
 * Author: Hisilicon
 * Version: Initial Draft
 * Create: 2020-01-16
 */

#ifndef __TEE_DRV_NPU_PM_H__
#define __TEE_DRV_NPU_PM_H__

/******************************************************************************/
/*                      SOC CRG Registers' Definitions                            */
/******************************************************************************/
// DTS: <0x0 0xa00000 0x0 0x1000>,   /* SYS_CRG */
#define SOC_CRG186_OFFSET                          0x2E8 /* NPU-1��ص�ʱ�Ӽ���λ���ƼĴ��� */
#define SOC_CRG187_OFFSET                          0x2EC /* NPU-2��ص�ʱ�Ӽ���λ���ƼĴ��� */
#define SOC_CRG188_OFFSET                          0x2F0 /* NPU-3��ص�ʱ�Ӽ���λ���ƼĴ��� */
#define SOC_CRG347_OFFSET                          0x56C /* APB-1ģ��ʱ����λ���ƼĴ��� */
#define SOC_CRG461_OFFSET                          0x734 /* HPM/SHPM/CPM ʱ�Ӹ�λ���üĴ��� */

/******************************************************************************/
/*                      SOC PERI Registers' Definitions                            */
/******************************************************************************/
// DTS: <0x0 0xa10000 0x0 0x1000>,   /* SYS_PERI_CTRL */
#define SOC_PERI_NPU_CTRL0_OFFSET                  0xc84 /* NPUϵͳ���ƼĴ���0 */
#define SOC_PERI_NPU_CTRL1_OFFSET                  0xc88 /* NPUϵͳ���ƼĴ���1 */
#define SOC_PERI_NPU_STAT0_OFFSET                  0xca4 /* NPU״̬�Ĵ���0 */
#define SOC_PERI_NPU_STAT1_OFFSET                  0xca8 /* NPU״̬�Ĵ���1 */

/******************************************************************************/
/*                      SOC PMC Registers' Definitions                            */
/******************************************************************************/
// DTS: <0x0 0xa15000 0x0 0x1000>,	/* SYS_PMC */
#define SOC_PMC_NPU_PWRUP_CTRL_OFFSET      0xc00 /* NPU���µ���ƼĴ�������ȫCPU��д */
#define SOC_PMC_CPU_PWRUP_CTRL_OFFSET      0xc80 /* CPU���µ���ƼĴ�������ȫCPU��д */
#define SOC_PMC_PWM4_CTRL2_OFFSET          0xe88 /* PWM4���üĴ�������ȫCPU��д */
#define SOC_PMC_PWM5_CTRL0_OFFSET          0xe90 /* PWM5��صĿ��ƼĴ�����NPU��ѹ��ʹ�á���ȫCPU��д */
#define SOC_PMC_PWM5_CTRL2_OFFSET          0xe98 /* PWM5���üĴ�������ȫCPU��д */
#define SOC_PMC_HPM5_CTRL0_OFFSET          0x5a0 /* HPM5��صĿ��ƼĴ�����NPU��ѹ��ʹ�� */
#define SOC_PMC_HPM5_CTRL1_OFFSET          0x5a4 /* HPM5��ص�״̬�Ĵ���1��NPU��ѹ��ʹ�� */
#define SOC_PMC_HPM5_CTRL2_OFFSET          0x5a8 /* HPM5��ص�״̬�Ĵ���2��NPU��ѹ��ʹ�� */
#define SOC_PMC_HPM5_CTRL4_OFFSET          0x5b0 /* HPM5�������üĴ�����NPU��ѹ��ʹ�� */
#define SOC_PMC_HPM5_CTRL3_OFFSET          0xd50 /* HPM5�������üĴ�����NPU��ѹ��ʹ�� */
#define SYS_CTRL_SC_GEN56_OFFSET           0x1880 /* HPM5�������üĴ�����NPU��ѹ��ʹ�� */

/******************************************************************************/
/*             SOC TS_SUBSYS Registers' Definitions                           */
/*             DTS: <0x0 0x4000000 0x0 0x400000>                              */
/******************************************************************************/
// ------------ SOC TS_SYSCTRL Registers' Definitions ------------
#define SOC_TS_SYSCTRL_SUBMODULE_OFFSET   (0x2000)   /* ���TS_SUBSYS��ƫ���� */

#define SOC_TS_SYSCTRL_SC_CTRL_OFFSET                 0x0             /* Reserved */
#define SOC_TS_SYSCTRL_SC_SYSSTAT0_OFFSET             0x8             /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT1_OFFSET             0xC             /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT2_OFFSET             0x10            /* AXI����deadlock DFX�Ĵ����� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT3_OFFSET             0x14            /* AXI����deadlock �˿�״̬�Ĵ����� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT4_OFFSET             0x18            /* TS CPU״ָ̬ʾ�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT5_OFFSET             0x1C            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT6_OFFSET             0x20            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT7_OFFSET             0x24            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT8_OFFSET             0x28            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT9_OFFSET             0x2C            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT10_OFFSET            0x30            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT11_OFFSET            0x34            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT12_OFFSET            0x38            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT13_OFFSET            0x3C            /* ������ */
#define SOC_TS_SYSCTRL_SC_SYSSTAT14_OFFSET            0x40            /* TSCPU״̬�Ĵ���0�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT15_OFFSET            0x44            /* TSCPU״̬�Ĵ���1�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT16_OFFSET            0x48            /* TSCPU״̬�Ĵ���2�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT17_OFFSET            0x4C            /* TSCPU״̬�Ĵ���3�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT18_OFFSET            0x50            /* TSCPU״̬�Ĵ���4�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT19_OFFSET            0x54            /* TSCPU״̬�Ĵ���5�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT20_OFFSET            0x58            /* TSCPU״̬�Ĵ���6�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT21_OFFSET            0x5C            /* TSCPU״̬�Ĵ���7�� */
#define SOC_TS_SYSCTRL_SC_SYSSTAT22_OFFSET            0x60            /* TSCPU״̬�Ĵ���15�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL0_OFFSET             0x9C            /* CPU���ƼĴ���0�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL1_OFFSET             0xA0            /* CPU���ƼĴ���1�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL2_OFFSET             0xA4            /* TS ���⹦�ܿ��ƼĴ���2�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL3_OFFSET             0xA8            /* TS CRG��idle�Զ���Ƶ���ƣ�����miniʹ�ã��� */
#define SOC_TS_SYSCTRL_PERIPHCTRL4_OFFSET             0xAC            /* TS AXI BUSӲ���Զ��ſ�ʹ�ܼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL5_OFFSET             0xB0            /* TS AXI���߹���״̬����Ĵ��� */
#define SOC_TS_SYSCTRL_PERIPHCTRL6_OFFSET             0xB4            /* CPU����������üĴ���0�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL7_OFFSET             0xB8            /* CPU����������üĴ���1�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL8_OFFSET             0xBC            /* CPUʱ���ſ�ʹ�ܼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL9_OFFSET             0xC0            /* CPUʱ���ſؽ�ֹ�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL10_OFFSET            0xC4            /* CPUʱ���ſ�״̬�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL11_OFFSET            0xC8            /* CPU��λʹ�ܼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL12_OFFSET            0xCC            /* CPU��λ����Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL13_OFFSET            0xD0            /* CPU��λ״̬�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL14_OFFSET            0xD4            /* TS�ڲ���QOS���üĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL15_OFFSET            0xD8            /* TS Timer64���ƼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL16_OFFSET            0xDC            /* ������ */
#define SOC_TS_SYSCTRL_PERIPHCTRL17_OFFSET            0xE0            /* TS DOORBELL MEM���ƼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL18_OFFSET            0xE4            /* TS SRAM MEM���ƼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL19_OFFSET            0xE8            /* TS AXI BUS�������ȼ����ƼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL20_OFFSET            0xEC            /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL21_OFFSET            0xF0            /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL22_OFFSET            0xF4            /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL23_OFFSET            0xF8            /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL24_OFFSET            0xFC            /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL25_OFFSET            0x100           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL26_OFFSET            0x104           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL27_OFFSET            0x108           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL28_OFFSET            0x10C           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL29_OFFSET            0x110           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL30_OFFSET            0x114           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL31_OFFSET            0x118           /* CPU MEM�����źš� */
#define SOC_TS_SYSCTRL_PERIPHCTRL32_OFFSET            0x11C           /* TS��ַ�����Ĵ��� */
#define SOC_TS_SYSCTRL_PERIPHCTRL33_OFFSET            0x120           /* ������ */
#define SOC_TS_SYSCTRL_PERIPHCTRL34_OFFSET            0x124           /* ������ */
#define SOC_TS_SYSCTRL_PERIPHCTRL35_OFFSET            0x128           /* TS�ڲ�ģ��ʱ���ſ�ʹ�ܼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL36_OFFSET            0x12C           /* TS�ڲ�ģ��ʱ���ſؽ�ֹ�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL37_OFFSET            0x130           /* TS�ڲ�ģ��ʱ���ſ�״̬�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL38_OFFSET            0x134           /* TS�ڲ�ģ����λʹ�ܼĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL39_OFFSET            0x138           /* TS�ڲ�ģ����λ����Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL40_OFFSET            0x13C           /* TS�ڲ�ģ����λ״̬�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL41_OFFSET            0x140           /* TS AXI�������ߵ�AWUSER�����źŵı���λ31:0�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL42_OFFSET            0x144           /* TS AXI�������ߵ�AWUSER�����źŵı���λ63:32�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL43_OFFSET            0x148           /* TS AXI�������ߵ�AWUSER�����źŵı���λ67:64�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL44_OFFSET            0x14C           /* TS AXI�������ߵ�ARUSER�����źŵı���λ31:0�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL45_OFFSET            0x150           /* TS AXI�������ߵ�ARUSER�����źŵı���λ63:32�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL46_OFFSET            0x154           /* TS AXI�������ߵ�ARUSER�����źŵı���λ67:64�Ĵ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL47_OFFSET            0x158           /* ������ */
#define SOC_TS_SYSCTRL_PERIPHCTRL48_OFFSET            0x15C           /* TS�ڲ���HINT_SYSCACHE���üĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL49_OFFSET            0x160           /* TS DPM�ļ�����üĴ����� */
#define SOC_TS_SYSCTRL_PERIPHCTRL50_OFFSET            0x164           /* TSCPU���ƼĴ���0�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL52_OFFSET            0x16C           /* TSCPU���ƼĴ���2�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL53_OFFSET            0x170           /* TSCPU���ƼĴ���3�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL55_OFFSET            0x178           /* TSCPU���ƼĴ���5�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL57_OFFSET            0x180           /* TSCPU���ƼĴ���7�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL58_OFFSET            0x184           /* TSCPU���ƼĴ���8�� */
#define SOC_TS_SYSCTRL_PERIPHCTRL59_OFFSET            0x188           /* TSCPU���ƼĴ���9�� */
#define SOC_TS_SYSCTRL_SC_TESTREG0_OFFSET             0xBE0           /* ������ԼĴ���0�� */
#define SOC_TS_SYSCTRL_SC_TESTREG1_OFFSET             0xBE4           /* ������ԼĴ���1�� */
#define SOC_TS_SYSCTRL_SC_TESTREG2_OFFSET             0xBE8           /* ������ԼĴ���2�� */
#define SOC_TS_SYSCTRL_SC_TESTREG3_OFFSET             0xBEC           /* ������ԼĴ���3�� */
#define SOC_TS_SYSCTRL_SC_TESTREG4_OFFSET             0xBF0           /* ������ԼĴ���4�� */
#define SOC_TS_SYSCTRL_SC_TESTREG5_OFFSET             0xBF4           /* ������ԼĴ���5�� */
#define SOC_TS_SYSCTRL_SC_TESTREG6_OFFSET             0xBF8           /* ������ԼĴ���6�� */
#define SOC_TS_SYSCTRL_SC_TESTREG7_OFFSET             0xBFC           /* ������ԼĴ���7�� */
#define SOC_TS_SYSCTRL_SC_TESTREG8_OFFSET             0xC00           /* ������ԼĴ���8�� */
#define SOC_TS_SYSCTRL_SC_TESTREG9_OFFSET             0xC04           /* ������ԼĴ���9�� */
#define SOC_TS_SYSCTRL_SC_TESTREG10_OFFSET            0xC08           /* ������ԼĴ���10�� */
#define SOC_TS_SYSCTRL_SC_TESTREG11_OFFSET            0xC0C           /* ������ԼĴ���11�� */
#define SOC_TS_SYSCTRL_SC_TESTREG12_OFFSET            0xC10           /* ������ԼĴ���12�� */
#define SOC_TS_SYSCTRL_SC_TESTREG13_OFFSET            0xC14           /* ������ԼĴ���13�� */
#define SOC_TS_SYSCTRL_SC_TESTREG14_OFFSET            0xC18           /* ������ԼĴ���14�� */
#define SOC_TS_SYSCTRL_SC_TESTREG15_OFFSET            0xC1C           /* ������ԼĴ���15�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG0_OFFSET             0xC20           /* Ӳ���ź����Ĵ���0�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG1_OFFSET             0xC24           /* Ӳ���ź����Ĵ���1�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG2_OFFSET             0xC28           /* Ӳ���ź����Ĵ���2�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG3_OFFSET             0xC2C           /* Ӳ���ź����Ĵ���3�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG4_OFFSET             0xC30           /* Ӳ���ź����Ĵ���4�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG5_OFFSET             0xC34           /* Ӳ���ź����Ĵ���5�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG6_OFFSET             0xC38           /* Ӳ���ź����Ĵ���6�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG7_OFFSET             0xC3C           /* Ӳ���ź����Ĵ���7�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG8_OFFSET             0xC40           /* Ӳ���ź����Ĵ���8�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG9_OFFSET             0xC44           /* Ӳ���ź����Ĵ���9�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG10_OFFSET            0xC48           /* Ӳ���ź����Ĵ���10�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG11_OFFSET            0xC4C           /* Ӳ���ź����Ĵ���11�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG12_OFFSET            0xC50           /* Ӳ���ź����Ĵ���12�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG13_OFFSET            0xC54           /* Ӳ���ź����Ĵ���13�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG14_OFFSET            0xC58           /* Ӳ���ź����Ĵ���14�� */
#define SOC_TS_SYSCTRL_SC_SEMAREG15_OFFSET            0xC5C           /* Ӳ���ź����Ĵ���15�� */
#define SOC_TS_SYSCTRL_SC_TESTREG16_OFFSET            0xC60           /* ������ԼĴ���16�� */
#define SOC_TS_SYSCTRL_SC_TESTREG17_OFFSET            0xC64           /* ������ԼĴ���17�� */
#define SOC_TS_SYSCTRL_SCPROTREG_OFFSET               0xC68           /* TS��λ�����Ĵ����� */

// ------------ SOC ts_tbu Registers' Definitions ----------------
#define SOC_NPU_HWTS_TBU_SUBMODULE_OFFSET   (0x100000)   /* ���TS_SUBSYS=0x4000000��ƫ���� */

/******************************************************************************/
/*                      SOC NPU_CRG Register module Definitions               */
/*                      DTS: <0x0 0x5e00000 0x0 0x200000>   NPU_CRG           */
/******************************************************************************/
// ------------ SOC NPU_TZPC Registers' Definitions ----------------
#define SOC_NPU_TZPC_SUBMODULE_OFFSET   (0x2000)   /* ���NPU_CFG=0x5e00000��ƫ���� */

// ------------------ SOC NPU_CRG Registers' Definitions ------------------
#define SOC_NPU_CRG_SUBMODULE_OFFSET                (0x3000)    /* ���NPU_CFG=0x5e00000��ƫ���� */

#define SOC_NPU_CRG_PEREN0_OFFSET                   (0x0)   /* ����ʱ��ʹ�ܼĴ���0 */
#define SOC_NPU_CRG_PERSTAT0_OFFSET                 (0xC)   /* ����ʱ������״̬�Ĵ���0 */
#define SOC_NPU_CRG_PEREN1_OFFSET                   (0x10) /* ����ʱ��ʹ�ܼĴ���1 */
#define SOC_NPU_CRG_PEREN2_OFFSET                   (0x20) /* ����ʱ��ʹ�ܼĴ���2 */
#define SOC_NPU_CRG_PEREN3_OFFSET                   (0x30) /* ����ʱ��ʹ�ܼĴ���3 */
#define SOC_NPU_CRG_PERRSTDIS0_OFFSET               (0x44) /* ������λ����Ĵ���0 */
#define SOC_NPU_CRG_PERRSTDIS1_OFFSET               (0x50) /* ������λ����Ĵ���1 */
#define SOC_NPU_CRG_PERRSTDIS2_OFFSET               (0x5c) /* ������λ����Ĵ���2 */
#define SOC_NPU_CRG_CLKDIV0_OFFSET                  (0x70) /* ʱ�ӷ�Ƶ�ȿ��ƼĴ���0 */
#define SOC_NPU_CRG_PERI_CTRL0_OFFSET               (0x84) /* ������ƼĴ���0 */
#define SOC_NPU_CRG_PPLL5CTRL0_OFFSET               (0x198) /* PPLL5���ƼĴ���0 */
#define SOC_NPU_CRG_PPLL5CTRL1_OFFSET               (0x19c) /* PPLL5���ƼĴ���1 */

// ------------------ SOC NPU_EASC_CFG Registers' Definitions  ------------------
#define SOC_NPU_EASC_CFG_SUBMODULE_OFFSET   (0xc000)    /* ���NPU_CFG=0x5e00000��ƫ���� */

// ------------ SOC aic0_smmu_cfg (AIC0(smmu_tbu)) Registers' Definitions ----------------
#define SOC_NPU_AICORE_TBU_SUBMODULE_OFFSET   (0x180000)   /* ���NPU_CFG=0x5e00000��ƫ���� */

// ------------ SOC sysdma_smmu_cfg (SYSDMA(smmu_tbu)) Registers' Definitions ------------
#define SOC_NPU_SYSDMA_TBU_SUBMODULE_OFFSET   (0x1A0000)   /* ���NPU_CFG=0x5e00000��ƫ���� */

// ------------------ SOC SMMU_TCU_CFG Registers' Definitions ------------------
#define SOC_SMMU_TCU_CFG_SUBMODULE_OFFSET   (0x1c0000)   /* ���NPU_CFG=0x5e00000��ƫ���� */

#define SOC_SMMU_CR0_OFFSET                  0x20  /* Non-secure global Control Register 0 */
#define SOC_SMMU_CR0ACK_OFFSET               0x24  /* Non-secure global Control Register 0 update Acknowledge register */
#define SOC_SMMU_CR2_OFFSET                  0x2c  /* Non-secure global Control Register 2 */
#define SOC_SMMU_STRTAB_BASE_CFG_OFFSET      0x88  /* Non-secure Stream Table Configuration register */
#define SOC_SMMU_CMDQ_PROD_OFFSET            0x98  /* Non-secure Command queue Producer index register */
#define SOC_SMMU_CMDQ_CONS_OFFSET            0x9c  /* Non-secure Command queue Consumer index register */

#define SOC_SMMU_S_CR0_OFFSET                0x8020  /* Secure global Control Register 0 */
#define SOC_SMMU_S_CR0ACK_OFFSET             0x8024  /* Secure global Control Register 0 update Acknowledge register */
#define SOC_SMMU_S_CR2_OFFSET                0x802c  /* Secure global Control Register 2 */
#define SOC_SMMU_S_INIT_OFFSET               0x803c  /* Secure Initialization control register */
#define SOC_SMMU_S_STRTAB_BASE_CFG_OFFSET    0x8088  /* Secure Stream Table Configuration register */
#define SOC_SMMU_S_CMDQ_PROD_OFFSET          0x8098  /* Secure Command queue Producer index register */
#define SOC_SMMU_S_CMDQ_CONS_OFFSET          0x809c  /* Secure Command queue Consumer index register */
#define SOC_SMMU_S_EVENTQ_PROD_OFFSET        0x80a8  /* Secure Event queue Producer index register */
#define SOC_SMMU_S_EVENTQ_CONS_OFFSET        0x80ac  /* Secure Event queue Consumer index register */

#define SOC_SMMU_TCU_LP_REQ_OFFSET           0x30000  /* SMMU TCU low-power request register */
#define SOC_SMMU_TCU_LP_ACK_OFFSET           0x30004  /* SMMU TCU low-power acknowledge register */
#define SOC_SMMU_TCU_IRPT_MASK_NS_OFFSET     0x30070  /* SMMU TCU non-secure interrupt mask register */
#define SOC_SMMU_TCU_IRPT_MASK_S_OFFSET      0x30080  /* SMMU TCU secure interrupt mask register */

#define HISI_TOP_CTL_BASE (0x30000)

#define SMMU_LP_REQ (HISI_TOP_CTL_BASE + 0)
#define TCU_QREQN_CG BIT(0)
#define TCU_QREQN_PD BIT(1)

#define SMMU_LP_ACK (HISI_TOP_CTL_BASE + 0x4)
#define TCU_QACCEPTN_CG BIT(0)
#define TCU_QACCEPTN_PD BIT(4)

#define SMMU_IRPT_MASK_NS (HISI_TOP_CTL_BASE + 0x70)
#define TCU_EVENT_TO_MASK BIT(5)
#define HISI_VAL_MASK 0xffffffff

#define SMMU_IRPT_RAW_NS (HISI_TOP_CTL_BASE + 0x74)

#define SMMU_IRPT_STAT_NS (HISI_TOP_CTL_BASE + 0x78)
#define TCU_EVENT_Q_IRQ BIT(0)
#define TCU_CMD_SYNC_IRQ BIT(1)
#define TCU_GERROR_IRQ BIT(2)

#define SMMU_IRPT_CLR_NS (HISI_TOP_CTL_BASE + 0x7c)
#define TCU_EVENT_Q_IRQ_CLR BIT(0)
#define TCU_CMD_SYNC_IRQ_CLR BIT(1)
#define TCU_GERROR_IRQ_CLR BIT(2)
#define TCU_EVENTTO_CLR BIT(5)

extern int npu_drv_power_on(void);
int hisi_npu_power_off(void);

#endif
