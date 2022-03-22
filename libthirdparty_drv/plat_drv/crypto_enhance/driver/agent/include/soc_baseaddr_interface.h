/****************************************************************************//**
 * @file   : soc_baseaddr_interface.h
 * @brief  :
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/05/16
 * @author : w00371137, wangyuzhu4@@huawei.com
 * @note   :
********************************************************************************/
#ifndef __SOC_BASEADDR_INTERFACE_H__
#define __SOC_BASEADDR_INTERFACE_H__

#include <soc_acpu_baseaddr_interface.h>


/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
/* ICCM ROM */
#define SOC_DCCM_ROM_BSP_SIZE                              (0x1000) /* 4KB */
#define SOC_ICCM_ROM_BASE_ADDR                             (0x00000000)
#define SOC_ICCM_ROM_SIZE                                  (0x00008000) /* 32KB */

/* ICCM RAM */
#define SOC_ICCM_RAM_BASE_ADDR                             (0x00008000)
#define SOC_ICCM_RAM_SIZE                                  (0x00018000) /* 96KB */

/* 0x00020000~0x20000000,reserved */

/* DCCM RAM */
#define SOC_DCCM_RAM_BASE_ADDR                             (0x20000000)
#define SOC_DCCM_RAM_SIZE                                  (0x00008000) /* 32KB */

#define HIEPS_DCCM_AUTOTEST_ADDR                          (SOC_DCCM_RAM_BASE_ADDR)
#if defined(FEATURE_AUTOTEST) && defined(FEATURE_LINK_TO_DDR)
#define HIEPS_DCCM_AUTOTEST_SIZE                          (0x3000)      /* 12K */
#else
#define HIEPS_DCCM_AUTOTEST_SIZE                          (0)
#endif /* FEATURE_AUTOTEST && FEATURE_LINK_TO_DDR */

/* 0x20008000~0x49400000,reserved */

/* config registers */
#define SOC_CONFIG_BASE_ADDR                               (0x49400000)
#define SOC_CONFIG_SIZE                                    (0x00001000) /* 4KB */

#define SOC_ETZPC_BASE_ADDR                                (0x49401000)
#define SOC_ETZPC_SIZE                                     (0x00001000) /* 4KB */

#define SOC_TRNG_BASE_ADDR                                 (0x49402000)
#define SOC_TRNG_SIZE                                      (0x00002000) /* 8KB */

#define SOC_TIMER_BASE_ADDR                                (0x49404000)
#define SOC_TIMER_SIZE                                     (0x00001000) /* 4KB */

#define SOC_WDG_BASE_ADDR                                  (0x49405000)
#define SOC_WDG_SIZE                                       (0x00001000) /* 4KB */

#define SOC_UART_BASE_ADDR                                 (0x49406000)
#define SOC_UART_SIZE                                      (0x00001000) /* 4KB */

#define SOC_IPC_BASE_ADDR                                  (0x49407000)
#define SOC_IPC_SIZE                                       (0x00001000) /* 4KB */

/* 0x49408000~0x49420000,reserved */

#define SOC_KM_BASE_ADDR                                   (0x49420000)
#define SOC_KM_SIZE                                        (0x00001000) /* 4KB */

#define SOC_SCE_BASE_ADDR                                  (0x49421000)
#define SOC_SCE_SIZE                                       (0x00001000) /* 4KB */

#define SOC_PKE_BASE_ADDR                                  (0x49422000)
#define SOC_PKE_SIZE                                       (0x00004000) /* 16KB */

/* 8k */
#define SOC_SM2_BASE_ADDR                             SOC_PKE_BASE_ADDR
#define SOC_SM2_SIZE                                  (0x00002000)
#define SOC_ECC_BASE_ADDR                             SOC_PKE_BASE_ADDR
#define SOC_ECC_SIZE                                  (0x00002000)

/* 8k */
#define SOC_RSA_BASE_ADDR                             (SOC_PKE_BASE_ADDR + SOC_ECC_SIZE)
#define SOC_RSA_SIZE                                  (0x00002000)

/* 0x49426000~0x49430000,reserved */

#define SOC_MMU_BASE_ADDR                                  (0x49430000)
#define SOC_MMU_SIZE                                       (0x00010000) /* 64KB */

/* 0x60000000~0x80000000, DDR(512MB) */

/* HISEE IPC */
#define SOC_HISEE_IPC_BASE_ADDR                            (0x5A230000)

/* HISEE MAILBOX */
#define SOC_HISEE_MBX_BASE_ADDR                            (0x5A220000)
#define SOC_HISEE_MBX_SIZE                                 (0x00004000)

/* ARC access DDR */
#define SOC_DDR_BASE_ADDR                                  (0x60000000)
#define SOC_DDR_WINDOW_SIZE                                (0x20000000)

#endif /* __SOC_BASEADDR_INTERFACE_H__ */

