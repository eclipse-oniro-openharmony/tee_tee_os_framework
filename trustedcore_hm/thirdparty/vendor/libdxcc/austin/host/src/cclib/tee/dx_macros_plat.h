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

#ifndef DX_MACROS_PLAT_H
#define DX_MACROS_PLAT_H

#include "dx_cc_regs.h"
#include "dx_reg_common.h"

#define IS_VALID_DCACHE_ADDR(addr) (0)
#define IS_VALID_ICACHE_ADDR(addr) (0)
#define IS_VALID_CACHE_ADDR(addr)  (0)

/* temp solution for SRAM size in CC44 */
/* #define SEP_SRAM_SIZE_GET()\
    (1 << (DX_CC_REG_FLD_GET(SEP_RGF, SEP_BOOT, SRAM_SIZE, DX_HAL_ReadCcRegister(DX_CC_REG_ADDR(SEP_RGF, SEP_BOOT))) +
   11)) */

#define SEP_SRAM_SIZE_GET()      12 * 1024
#define IS_VALID_SRAM_ADDR(addr) (((uint32_t)(addr)) < SEP_SRAM_SIZE_GET())
#endif /* DX_MACROS_PLAT_H */
