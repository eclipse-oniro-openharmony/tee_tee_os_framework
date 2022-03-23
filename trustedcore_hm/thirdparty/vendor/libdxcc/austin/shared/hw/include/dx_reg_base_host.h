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

#ifndef __DX_REG_BASE_HOST_H__
#define __DX_REG_BASE_HOST_H__

/* Identify platform: Xilinx Zynq7000 ZC706 */
#define DX_PLAT_ZYNQ7000       1
#define DX_PLAT_ZYNQ7000_ZC706 1

#define DX_BASE_ENV_REGS        0x40008000
#define DX_BASE_ENV_CC_MEMORIES 0x40008000
#define DX_BASE_ENV_PERF_RAM    0x40009000

#define DX_BASE_HOST_RGF   0x0UL
#define DX_BASE_CRY_KERNEL 0x0UL
#define DX_BASE_ROM        0x40000000

#define DX_BASE_RNG 0x0000UL

#endif /* __DX_REG_BASE_HOST_H__ */
