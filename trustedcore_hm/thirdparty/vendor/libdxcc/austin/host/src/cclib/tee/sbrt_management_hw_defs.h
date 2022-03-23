/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef _SBRT_MNG_HW_DEFS_H
#define _SBRT_MNG_HW_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dx_hal_plat.h"

/* ********************** Macros ******************************* */

/* Check Provision error bit in LCS register */
#define DX_SBRT_IS_OTP_PROV_ERROR(regVal)                                      \
    do {                                                                       \
        regVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, LCS_REG)); \
        regVal = DX_CC_REG_FLD_GET(0, LCS_REG, ERROR_PROV_ZERO_CNT, regVal);   \
    } while (0)

/* Poll on the AIB acknowledge bit */
#define DX_SBRT_WAIT_ON_AIB_ACK_BIT()                                                   \
    do {                                                                                \
        uint32_t regVal;                                                                \
        do {                                                                            \
            regVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, AIB_FUSE_ACK)); \
        } while (!(regVal & 0x1));                                                      \
    } while (0)

/* Poll on the AIB prog complete bit */
#define DX_SBRT_WAIT_ON_AIB_PROG_COMP_BIT()                                                        \
    do {                                                                                           \
        uint32_t regVal;                                                                           \
        do {                                                                                       \
            regVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, AIB_FUSE_PROG_COMPLETED)); \
            regVal = DX_CC_REG_FLD_GET(0, AIB_FUSE_PROG_COMPLETED, VALUE, regVal);                 \
        } while (!regVal);                                                                         \
    } while (0)

/* Read a word via NVM */
#define DX_SBRT_READ_WORD_VIA_AIB(nvmAddr, nvmData)                                        \
    do {                                                                                   \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, HOST_AIB_ADDR_REG), nvmAddr);  \
        DX_SBRT_WAIT_ON_AIB_ACK_BIT();                                                     \
        nvmData = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, HOST_AIB_RDATA_REG)); \
    } while (0)

/* Write a word via NVM */
#define DX_SBRT_WRITE_WORD_VIA_AIB(nvmAddr, nvmData)                                       \
    do {                                                                                   \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, HOST_AIB_WDATA_REG), nvmData); \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, HOST_AIB_ADDR_REG), nvmAddr);  \
        DX_SBRT_WAIT_ON_AIB_ACK_BIT();                                                     \
        DX_SBRT_WAIT_ON_AIB_PROG_COMP_BIT();                                               \
    } while (0)

/* ********************** Defines ******************************* */

#define DX_VERSION_PRODUCT_BIT_SHIFT 0x18UL
#define DX_VERSION_PRODUCT_BIT_SIZE  0x8UL

/* NVM definitions */
#define DX_SBRT_NVM_READ_ADDR  (0x1 << DX_HOST_AIB_ADDR_REG_READ_ACCESS_BIT_SHIFT)
#define DX_SBRT_NVM_WRITE_ADDR (0x1 << DX_HOST_AIB_ADDR_REG_WRITE_ACCESS_BIT_SHIFT)

#ifdef __cplusplus
}
#endif

#endif
