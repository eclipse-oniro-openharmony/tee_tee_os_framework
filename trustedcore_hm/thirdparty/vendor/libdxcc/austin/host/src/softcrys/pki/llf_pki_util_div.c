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

/* ************ Include Files ************** */

#include "dx_pal_mem.h"
#include "dx_pal_types.h"
#include "sw_llf_pki_error.h"
#include "sw_llf_pki_error.h"

/* *********************** Defines **************************** */

/* canceling the PC-lint warning:
   Unusual pointer cast (incompatible indirect types) */


/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* ************ Private function prototype ************** */

/* *********************** Public Functions **************************** */

/*
 * ==================================================================
 * Function name: LLF_PKI_UTIL_digitDiv
 *
 * Description: This function divides two big numbers.
 *
 *              algorithm:
 *
 * Computes q = b / c,
 * where b is two digits number ,
 * b[1] < c so q is one digit number ,
 * MSB of c is one.
 * Simulates SUBC instruction.
 *
 * Author: Victor Elkonin,
 *
 * Last Rivision: 1.00.00
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

uint32_t LLF_PKI_UTIL_digitDiv(uint32_t *b_ptr, uint32_t c)
{
    /* LOCAL DECLERATIONS */

    int32_t i;
    uint32_t num; /* numerator */
    uint32_t carry;
    uint32_t q = 0; /* quotient */

    /* FUNCTION LOGIC */

    num = b_ptr[1];

    for (i = 32 - 1; i >= 0; i--) {
        carry = num >> (32 - 1);
        num <<= 1;
        num += (b_ptr[0] >> i) & 1;
        q <<= 1;
        if (carry || (num >= c)) {
            num -= c;
            q++;
        }
    }

    return q;

} /* END OF LLF_PKI_UTIL_digitDiv */

/*
 * ==================================================================
 * Function name: LLF_PKI_UTIL_div
 *
 * Description: This function performs a division of two big numbers.
 *
 *
 * Computes modRes = b mod n. DivRes_ptr = floor(b/n)
 * Lengths: modRes[modLen], b[numLen], n[modLen], modRes_ptr[numLen],DivRes_ptr[numLen]
 *          tempBuff[2*modLen].
 * Assumes:
 * c > 0.
 *
 * Author: Victor Elkonin , adapted for 16 bit multiplication by R.Levin
 *
 * Last Revision: 1.00.00
 *
 * Method: Overestimation and correction.
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

void LLF_PKI_UTIL_div(uint32_t *b_ptr, uint32_t numSizeInWords, uint32_t *n_ptr, uint32_t modSizeInWords,
                      uint32_t *modRes_ptr, uint32_t *DivRes_ptr, uint32_t *tempBuff_ptr)

{
    /* LOCAL DECLERATIONS */

    /* Indexes  */
    int32_t i, j, k; /* shift; */

    uint32_t modLen, numLen;
    uint32_t *c_ptr, *bb_ptr, *cc_ptr;
    uint32_t quotient;
    uint32_t borrow;
    uint32_t t1, t2;
    volatile uint16_t *qL_ptr, *qH_ptr, *ccL_ptr, *ccH_ptr;
    uint32_t shift;

    /* FUNCTION LOGIC */

    /* ......................... initialize local variables ........................ */

    numLen = numSizeInWords;
    modLen = modSizeInWords;
    c_ptr  = n_ptr;                 /* pointer to modulo n */
    cc_ptr = tempBuff_ptr;          /* pointer to workingSpace of modulo using the low temp buffer */
    bb_ptr = tempBuff_ptr + modLen; /* pointer to workingSpace of numerator using the high temp buffer */

    /* Pointers for  multiplication 16*16 bits */
#ifndef BIG__ENDIAN
    qL_ptr  = (uint16_t *)&quotient;
    qH_ptr  = ((uint16_t *)&quotient) + 1;
    ccL_ptr = (uint16_t *)cc_ptr;
    ccH_ptr = ((uint16_t *)cc_ptr) + 1;
#else
    qL_ptr  = (uint16_t *)&quotient + 1;
    qH_ptr  = ((uint16_t *)&quotient);
    ccL_ptr = (uint16_t *)cc_ptr + 1;
    ccH_ptr = ((uint16_t *)cc_ptr);
#endif

    /* Set 0 to all words of DivRes_ptr */
    DX_PAL_MemSetZero(DivRes_ptr, numLen * sizeof(uint32_t));

    /* Search for most significant bit and lengths of modulo c  */
    while (c_ptr[--modLen] == 0) {
    }
    modLen++;

    /*   Shift left last word of modulo, so that the grown-up of
         bits is 1, and calculate of shift.                  */
    shift              = 0;
    cc_ptr[modLen - 1] = c_ptr[modLen - 1];
    while ((cc_ptr[modLen - 1] & (1UL << 31)) == 0) {
        shift++;
        cc_ptr[modLen - 1] <<= 1;
    }

    /*   Shift left each word of modulo n and numerator b on shift and write
         to cc and bb respectively    */
    bb_ptr[numLen] = 0;
    for (i = (int32_t)(modLen - 1); i > 0; i--) {
        /* we're handling the case of shift 0 due to a bug in
         * CodeWarrior for Symbian Personal v2.5
         */
        if (shift != 0) {
            cc_ptr[i] += c_ptr[i - 1] >> (32 - shift);
            cc_ptr[i - 1] = c_ptr[i - 1] << shift;
        } else
            cc_ptr[i - 1] = c_ptr[i - 1];
    }

    for (i = (int32_t)numLen; i > 0; i--) {
        /* we're handling the case of shift 0 due to a bug in
         * CodeWarrior for Symbian Personal v2.5
         */
        if (shift != 0) {
            bb_ptr[i] += b_ptr[i - 1] >> (32 - shift);
            bb_ptr[i - 1] = b_ptr[i - 1] << shift;
        } else
            bb_ptr[i - 1] = b_ptr[i - 1];
    }

    /*  Compute quotient = floor(b/n) and reminder  a = b mod n.  */
    /* -------------------------------------------------------------- */

    for (i = (int32_t)(numLen - modLen); i >= 0; i--) {
        /* Overestimate quotient digit and subtract. */
        if ((bb_ptr[(int32_t)modLen + i] == cc_ptr[modLen - 1]))

            quotient = 0xffffffff;
        else
            quotient = LLF_PKI_UTIL_digitDiv(&bb_ptr[(int32_t)modLen + i - 1], cc_ptr[modLen - 1]);

        borrow = 0;
        j      = 0;

        do {
            uint32_t temp, temp1, temp2, temp3, carry;

            k = 2 * j; /* index for pointer ccL to unsigned short cc[j] */

            temp          = bb_ptr[i + j];
            bb_ptr[i + j] = bb_ptr[i + j] - borrow;
            if (bb_ptr[i + j] > temp)
                borrow = 1;
            else
                borrow = 0;

            /* Compute (t1 t2) = quotient * cc[j], where t1, t2 - low and high halfs of multiple */
            /* Remark: the function simulates multiplication on 32*32 bits multiplier   */
            /*   */

            temp1 = t1 = (*qL_ptr) * ccL_ptr[k]; /* multiple of low words  of factors */
            temp2      = (*qL_ptr) * ccH_ptr[k];
            temp3      = (*qH_ptr) * ccL_ptr[k];

            t1 = t1 + (temp2 << 16);
            if (t1 < temp1)
                carry = 1;
            else
                carry = 0;

            temp1 = t1;
            t1    = t1 + (temp3 << 16);
            if (t1 < temp1)
                carry++;

            t2 = (*qH_ptr) * ccH_ptr[k] + (temp2 >> 16) + (temp3 >> 16) + carry;

            temp1         = bb_ptr[i + j];
            bb_ptr[i + j] = bb_ptr[i + j] - t1;
            if (bb_ptr[i + j] > temp1)
                borrow++;
            borrow = borrow + t2;

        } while (++j < (int32_t)modLen);

        bb_ptr[i + j] = (uint32_t)(bb_ptr[i + j] - borrow);

        /* Correct estimation. */

        /* Check the estimation: check if the numerator negative. */
        while (bb_ptr[i + (int32_t)modLen]) {
            uint32_t temp1;
            uint32_t carry = 0;

            /* Correct the quotient and add the divisor to the numerator. */
            quotient--;
            j = 0;

            do {
                temp1         = bb_ptr[i + j];
                bb_ptr[i + j] = bb_ptr[i + j] + carry;
                if (bb_ptr[i + j] < temp1)
                    carry = 1;
                else
                    carry = 0;

                temp1         = bb_ptr[i + j];
                bb_ptr[i + j] = bb_ptr[i + j] + cc_ptr[j];
                if (bb_ptr[i + j] < temp1)
                    carry++;

            } while (++j < (int32_t)modLen);

            bb_ptr[i + j] = (uint32_t)(bb_ptr[i + j] + carry);
        }

        DivRes_ptr[i] = quotient;
    }

    /* Reverse to non shifted representation   */
    for (i = 0; i < (int32_t)modSizeInWords; i++) {
        /* we're handling the case of shift 0 due to a bug in
         * CodeWarrior for Symbian Personal v2.5          */
        if (shift != 0) {
            modRes_ptr[i] = bb_ptr[i] >> shift;
            modRes_ptr[i] += bb_ptr[i + 1] << (32 - shift);
        } else
            modRes_ptr[i] = bb_ptr[i];
    }

    /* Write 0 to superfluous words of result a */
    DX_PAL_MemSetZero(modRes_ptr + modLen, (modSizeInWords - modLen) * sizeof(uint32_t));

    return;

} /* END OF LLF_PKI_UTIL_div */
