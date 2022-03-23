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

#ifndef __DX_HAL_PLAT_H__
#define __DX_HAL_PLAT_H__

#include "dx_host.h"
#include "dx_bitops.h"

#include "dx_reg_common.h" /* temporary (missing HW defines) */

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */
#define DX_LARGE_SECRET_KEY_NUM_OF_BYTES 32
#define DX_SMALL_SECRET_KEY_NUM_OF_BYTES 16

#define DX_HAL_ALIGN_OK            (0x0UL)
#define DX_HAL_ALIGN_INVALID_INPUT (0x1UL)

/* *****************************************************************************
 *                               MACROS
 * *************************************************************************** */
extern unsigned long gCcRegBase;

/* *****************************************************************************
 *                               MACROS
 * *************************************************************************** */
/* get the size of the RKEK from HW */
// (key_size >> DX_NVM_CC_BOOT_LARGE_RKEK_LOCAL_BIT_SHIFT) & DX_NVM_CC_BOOT_LARGE_RKEK_LOCAL_BIT_SIZE
#define GET_ROOT_KEY_SIZE(key_size)                                                  \
    do {                                                                             \
        key_size = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, NVM_CC_BOOT)); \
        if (DX_CC_REG_FLD_GET(CRY_KERNEL, NVM_CC_BOOT, LARGE_RKEK_LOCAL, key_size))  \
            key_size = DX_LARGE_SECRET_KEY_NUM_OF_BYTES;                             \
        else                                                                         \
            key_size = DX_SMALL_SECRET_KEY_NUM_OF_BYTES;                             \
    } while (0)

/* !
 * Read CryptoCell memory-mapped-IO register.
 *
 * \param regOffset The offset of the CC register to read
 * \return uint32_t Return the value of the given register
 */
#define DX_HAL_ReadCcRegister(regOffset) (*((volatile uint32_t *)(gCcRegBase + (regOffset))))

/* !
 * Write CryptoCell memory-mapped-IO register.
 *
 * \param regOffset The offset of the CC register to write
 * \param val The value to write
 */
#define DX_HAL_WriteCcRegister(regOffset, val) (*((volatile uint32_t *)(gCcRegBase + (regOffset))) = (val))

#endif /* __DX_HAL_PLAT_H__ */
