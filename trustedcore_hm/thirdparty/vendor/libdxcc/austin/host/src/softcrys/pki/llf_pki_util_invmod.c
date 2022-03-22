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

/* ************ Include Files ************** */

#include "dx_pal_mem.h"
#include "dx_pal_types.h"
#include "sw_llf_pki_error.h"
#include "llf_pki_util.h"
#ifdef DX_SOFT_KEYGEN
#include "ccsw_crys_rsa_types.h"
#endif

/* *********************** Defines **************************** */

/* canceling the PC-lint warning:
   Unusual pointer cast (incompatible indirect types) */

/* canceling the PC-lint warning:
   while(1) */


/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* ************ Private function prototype ************** */

/* *********************** Public Functions **************************** */

/*
 * ==================================================================
 * Function name: LLF_PKI_UTIL_InvMod
 *
 * Description: This function finds multiplicative inverse modulo prime number.
 *
 *
 *  Computes ordinary multiplicative inverse modulo prime number a=b^-1 mod p.
 *  Lengths: Result[digits], b[digits], p[digits], temp[8*digits].
 *  Assumes: 1. digits > 0.
 *           2. Result is not equal to b or p (pointers).
 *             3. p is prime.
 *             4. 0<b<p.
 *
 * Author: Victor Elkonin
 *
 * Last Rivision: 1.00.00
 *
 * Method: extended Euclidean algorithm.
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

void LLF_PKI_UTIL_InvMod(uint32_t *b, uint32_t *p, uint32_t *Result, uint32_t *temp_ptr, uint32_t digits)
{
    /* LOCAL INITIALIZTIONS AND VARIABLES */

    uint32_t *aa  = temp_ptr;
    uint32_t *bb  = aa + digits;
    uint32_t *y1  = bb + digits;
    uint32_t *y2  = y1 + digits;
    uint32_t *q   = y2 + digits;
    uint32_t *qy1 = q + digits;
    uint32_t *temp;
    uint32_t borrow, carry;
    uint32_t numLen;
    uint32_t modLen;
    int y2sign = -1;
    int i;
    unsigned int j;

    /* FUNCTION LOGIC */

    DX_PAL_MemCopy(aa, p, digits * sizeof(uint32_t));
    DX_PAL_MemCopy(bb, b, digits * sizeof(uint32_t));
    DX_PAL_MemSetZero(y1, 2 * digits * sizeof(uint32_t));
    y1[0] = 1;

    i      = (int32_t)digits;
    modLen = digits;
    numLen = digits;

    while (PLS_TRUE) {
        y2sign = -y2sign;

        LLF_PKI_UTIL_div(aa, numLen, bb, modLen, aa, q, temp_ptr + 6 * digits);

        /* swap aa and bb */
        temp = bb;
        bb   = aa;
        aa   = temp;

        /* compute y2=(y2+q*y1) */
        LLF_PKI_UTIL_ExecuteRMulOperation(q, (digits * 32), y1, qy1);

        carry = 0;

        for (j = 0; j < digits; j++) {
            if ((y2[j] += carry) < carry)
                y2[j] = qy1[j];
            else if ((y2[j] += qy1[j]) < qy1[j])
                carry = 1;
            else
                carry = 0;
        }

        /* swap y1 and y2 */
        temp = y1;
        y1   = y2;
        y2   = temp;

        while (--i >= 0)
            if (bb[i])
                break;

        if (i < 0)
            /* bb=0 */
            break;

        numLen = modLen;
        modLen = (uint32_t)(++i);
    }

    if (y2sign < 0) {
        /* y2=p-y2 */
        borrow = 0;
        for (i = 0; i < (int32_t)digits; i++) {
            if ((y2[i] += borrow) < borrow)
                y2[i] = p[i];
            else if ((y2[i] = p[i] - y2[i]) > p[i])
                borrow = 1;
            else
                borrow = 0;
        }

    } /* end of while PLS_TRUE */

    DX_PAL_MemCopy(Result, y2, digits * sizeof(uint32_t));

} /* END OF LLF_PKI_UTIL_InvMod */
