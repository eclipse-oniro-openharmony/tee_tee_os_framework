/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __SSI_HAL_PLAT_H__
#define __SSI_HAL_PLAT_H__

#include "dx_host.h"
#include "ssi_bitops.h"

#include "dx_reg_common.h" /* temporary (missing HW defines) */

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */
#define SASI_LARGE_SECRET_KEY_NUM_OF_BYTES 32
#define SASI_SMALL_SECRET_KEY_NUM_OF_BYTES 16

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
        key_size = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, NVM_CC_BOOT)); \
        if (SASI_REG_FLD_GET(CRY_KERNEL, NVM_CC_BOOT, LARGE_RKEK_LOCAL, key_size))   \
            key_size = SASI_LARGE_SECRET_KEY_NUM_OF_BYTES;                           \
        else                                                                         \
            key_size = SASI_SMALL_SECRET_KEY_NUM_OF_BYTES;                           \
    } while (0)

/* !
 * Read CryptoCell memory-mapped-IO register.
 *
 * \param regOffset The offset of the ARM CryptoCell register to read
 * \return uint32_t Return the value of the given register
 */
#define SASI_HAL_READ_REGISTER(regOffset) (*((volatile uint32_t *)(gCcRegBase + (regOffset))))

/* !
 * Write CryptoCell memory-mapped-IO register.
 *
 * \param regOffset The offset of the ARM CryptoCell register to write
 * \param val The value to write
 */
#define SASI_HAL_WRITE_REGISTER(regOffset, val) (*((volatile uint32_t *)(gCcRegBase + (regOffset))) = (val))

#endif /* __SSI_HAL_PLAT_H__ */
