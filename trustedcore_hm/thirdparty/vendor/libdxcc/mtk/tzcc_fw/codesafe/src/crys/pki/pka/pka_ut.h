/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_UT_H
#define PKA_UT_H

#include "pka_hw_defs.h"
#include "ssi_pal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ***************************************************** */
/* ********         FUNCTIONS PROTOTYPES     ******* */
/* ***************************************************** */

/*
 * The function transforms integer buffer K to NAF string.
 *
 * @author reuvenl (6/11/2014)
 *
 * @param [out] pNaf - The pointer to NAF key buffer (msb->lsb).
 * @param [in/out] pNafSz - The pointer to size in bytes of the NAF output.
 *        Input - size of user given buffer, output - actual size of NAF key.
 * @param [in]  pK - The pointer to key buffer. Note: the key buffer
 *          should be corrupted by the function.
 * @param [in]  keySz - The size of key in bits.
 *
 * @return uint32_t error message
 */
SaSiError_t pka_build_naf(char **pNaf, uint32_t *pNafSz, uint32_t *pK, uint32_t keySzBit);

/*
 * The function returns bit bi from register r.
 *
 *
 * @author reuvenl (6/12/2014)
 *
 * @param r  - register virt. pointer.
 * @param i  - index of the requirred bit.
 * @param pW - pointer to 32-bit current word, which must be saved by
 *         caller through reading bits from the register.
 * @param pIsNew -  pointer to indicator is a new start (pIsNew=1) of
 *             the function for this register. The value is updated
 *             to 0 by the function after start.
 *
 * @return uint32_t - bit's value
 */
uint32_t pka_getNextMsBit(uint32_t r, int32_t i, uint32_t *pW, uint32_t *pIsNew);

/*
 * The function returns 2 MS-bits from register r.
 *
 * @author reuvenl (6/12/2014)
 *
 * @param r  - register virt. pointer.
 * @param i  - index of the requirred two bits (must be even).
 * @param pW - pointer to 32-bit current word, which must be saved by
 *         caller through reading bits from the register.
 * @param pIsNew -  pointer to indicator is it a new start of
 *             the function for this register or not. The value is updated
 *             to FALSE by the function after start.
 *
 * @return uint32_t - bit's value
 */
uint32_t pka_get2msbits(uint32_t r, int32_t i, uint32_t *pW, uint32_t *pIsNew);

#ifdef __cplusplus
}
#endif

#endif
