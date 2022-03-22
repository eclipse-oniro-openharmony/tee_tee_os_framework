/*
 * Copyright c Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file define SOC base address for ARC. The whole memory
 *              map is in file soc_acpu_baseaddr_interface.h.
 * Author : w00371137, wangyuzhu4@@huawei.com
 * Create: 2019/04/13
*/

#ifndef __SOC_BASEADDR_INTERFACE_H__
#define __SOC_BASEADDR_INTERFACE_H__
#include <soc_acpu_baseaddr_interface.h>

/* ICCM ROM */
#define SOC_DCCM_ROM_BSP_SIZE       0x1000 /* 4KB */
#define SOC_ICCM_ROM_BASE_ADDR      SOC_ACPU_EPS_ICCM_RAM_BASE_ADDR
#define SOC_ICCM_ROM_SIZE           0x00008000 /* 32KB */

/* ICCM RAM */
#define SOC_ICCM_RAM_BASE_ADDR      SOC_ACPU_EPS_ICCM_RAM_BASE_ADDR
#define SOC_ICCM_RAM_SIZE           0x00018000 /* 96KB */

/* DCCM RAM */
#define SOC_DCCM_RAM_BASE_ADDR      SOC_ACPU_EPS_DCCM_RAM_BASE_ADDR
#define SOC_DCCM_RAM_SIZE           0x00008000 /* 32KB */

#define HIEPS_DCCM_AUTOTEST_ADDR    SOC_DCCM_RAM_BASE_ADDR
#if defined(FEATURE_AUTOTEST) && defined(FEATURE_LINK_TO_DDR)
#define HIEPS_DCCM_AUTOTEST_SIZE    0x5400      /* 21K */
#else
#define HIEPS_DCCM_AUTOTEST_SIZE                           0
#endif /* FEATURE_AUTOTEST && FEATURE_LINK_TO_DDR */

/* config registers */
/* 0x69500000 */
#define SOC_CONFIG_BASE_ADDR       SOC_ACPU_EPS_CONFIG_BASE_ADDR
#define SOC_CONFIG_SIZE            0x00001000 /* 4KB */

/* 0x69501000 */
#define SOC_ETZPC_BASE_ADDR        SOC_ACPU_EPS_ETZPC_BASE_ADDR
#define SOC_ETZPC_SIZE             0x00001000 /* 4KB */

#define SOC_TRNG_BASE_ADDR         SOC_ACPU_EPS_TRNG_BASE_ADDR
#define SOC_TRNG_SIZE              0x00002000 /* 8KB */

#define SOC_TIMER_BASE_ADDR        SOC_ACPU_EPS_TIMER_BASE_ADDR
#define SOC_TIMER_SIZE             0x00001000 /* 4KB */

#define SOC_WDG_BASE_ADDR          SOC_ACPU_EPS_WD_BASE_ADDR
#define SOC_WDG_SIZE               0x00001000 /* 4KB */

#define SOC_UART_BASE_ADDR         SOC_ACPU_EPS_UART_BASE_ADDR
#define SOC_UART_SIZE              0x00001000 /* 4KB */

#define SOC_IPC_BASE_ADDR          SOC_ACPU_EPS_IPC_BASE_ADDR
#define SOC_IPC_SIZE               0x00001000 /* 4KB */

/* 0x49408000~0x49420000,reserved */
#define SOC_SCE2_BASE_ADDR         SOC_ACPU_EPS_SCE2_BASE_ADDR
#define SOC_SCE2_SIZE              0x00001000 /* 4KB */

#define SOC_KM_BASE_ADDR           SOC_ACPU_EPS_KM_BASE_ADDR
#define SOC_KM_SIZE                0x00001000 /* 4KB */

#define SOC_SCE_BASE_ADDR          SOC_ACPU_EPS_SCE_BASE_ADDR
#define SOC_SCE_SIZE               0x00001000 /* 4KB */

/* Start of PKE */
#define SOC_PKE_BASE_ADDR          SOC_ACPU_EPS_PKE_BASE_ADDR
#define SOC_PKE_SIZE               0x00028000 /* 160KB */

#define SOC_SM2_BASE_ADDR          SOC_PKE_BASE_ADDR
#define SOC_SM2_SIZE               0x00002000 /* 8KB */
#define SOC_ECC_BASE_ADDR          SOC_PKE_BASE_ADDR
#define SOC_ECC_SIZE               0x00002000 /* 8KB */

#define SOC_RSA_BASE_ADDR          (SOC_PKE_BASE_ADDR + SOC_ECC_SIZE)
#define SOC_RSA_SIZE               0x00002000 /* 8KB */

#define SOC_REGFILE_BASE_ADDR      (SOC_RSA_BASE_ADDR + SOC_RSA_SIZE)
#define SOC_REGFILE_SIZE           0x00000800 /* 2KB */

#define SOC_SM9_IRAM0_BASE_ADDR    (SOC_REGFILE_BASE_ADDR + SOC_REGFILE_SIZE)
#define SOC_SM9_IRAM0_SIZE         0x00004000 /* 16KB */

#define SOC_SM9_IRAM1_BASE_ADDR    (SOC_SM9_IRAM0_BASE_ADDR + SOC_SM9_IRAM0_SIZE)
#define SOC_SM9_IRAM1_SIZE         0x00004000 /* 16KB */

#define SOC_SM9_DRAM_BASE_ADDR     (SOC_SM9_IRAM1_BASE_ADDR + SOC_SM9_IRAM1_SIZE)
#define SOC_SM9_DRAM_SIZE          0x0001B800 /* 110KB */

#define SOC_RSA2_BASE_ADDR         SOC_ACPU_EPS_PKE2_BASE_ADDR
#define SOC_RSA2_SIZE              0x00002000 /* 8KB */

#define SOC_RSA3_BASE_ADDR         (SOC_RSA2_BASE_ADDR + SOC_RSA2_SIZE)
#define SOC_RSA3_SIZE              0x00002000 /* 8KB */

/* End of PKE */

#define SOC_MMU_BASE_ADDR          SOC_ACPU_EPS_MMU_BASE_ADDR
#define SOC_MMU_SIZE               0x00003000 /* 12KB */


/* HISEE IPC */
#define SOC_HISEE_IPC_BASE_ADDR    SOC_ACPU_HISEE_IPC_BASE_ADDR

/* HISEE MAILBOX */
#define SOC_HISEE_MBX_BASE_ADDR    SOC_ACPU_HISEE_MAILBOX_BASE_ADDR
#define SOC_HISEE_MBX_SIZE         0x00004000 /* 16KB */

#define SOC_DDR_BASE_ADDR          SOC_ACPU_DDR_BASE_ADDR

#define SOC_ACTRL_BASE_ADDR        SOC_ACPU_ACTRL_BASE_ADDR

#endif /* __SOC_BASEADDR_INTERFACE_H__ */

