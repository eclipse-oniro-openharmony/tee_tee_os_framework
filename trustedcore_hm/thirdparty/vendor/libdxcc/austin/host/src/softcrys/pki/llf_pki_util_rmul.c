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

/* *********************** Defines **************************** */

/* canceling the PC-lint warning:
   Unusual pointer cast (incompatible indirect types) */


/* *********************** Enums ****************************** */

/* *********************** Typedefs *************************** */

/* *********************** Global Data ************************ */

/* ************ Exported function prototype ******************* */

/* ******************************************************************************************
 * @brief This function executes the RMUL operation.
 *
 *        The RMul operation is : (A * B)
 *
 *        The function performs the following algorithm:
 *
 *        INPUT: integers a = (a[n-1] a[n-2] a[n-3] .... a[0]),          a[i]) - unsigned int,
 *                        b = (b[n-1] b[n-2] b[n-3] .... b[0]),          b[i]) - unsigned int,
 *
 *        OUTPUT:result_ptr = (result_ptr[2*n-1] result_ptr[2*n-2] result_ptr[2*n-3] .... result_ptr[0]),result_ptr[i])
 * - unsigned int,
 *
 *        Lengths: result_ptr[2*n], a[n], b[n],   n = digits.
 *
 * Assumes: 1. digits > 0.
 *            2. a does not equal to b or c.
 *
 * Let: carry, carry1, temp - unsigned int integers.
 *
 *      1. For i from 0 to (n-1) do result_ptr[i] = 0.
 *      2. For i from 0 to (n-1) do the following:
 *            2.1. carry1 = 0.
 *            2.2. For j from 0 to (n-1) do the following:
 *                    2.2.1. temp = result_ptr[i+j].
 *                  2.2.2. result_ptr[i+j] = result_ptr[i+j] + (low half word of (a[i]*b[j]).
 *                    2.2.3. if result_ptr[i+j] < temp,  then carry = 1, else carry = 0.
 *                    2.2.4. temp = result_ptr[i+j+1].
 *                  2.2.5. result_ptr[i+j+1] = result_ptr[i+j+1] + (high half word of (a[i]*b[j]) +
 *                         + carry + carry1.
 *                    2.2.6. if result_ptr[i+j+1] < temp,  then carry1 = 1, else carry1 = 0.
 * 3. Return.
 *
 * @param[in] A_ptr - The pointer of A vector.
 * @param[in] B_ptr - The pointer of B vector.
 * @param[in] ASizeInBits - The size of vectors in bits.
 * @param[out] result - the vector of the result.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t LLF_PKI_UTIL_ExecuteRMulOperation(uint32_t *A_ptr, uint32_t ASizeInBits, uint32_t *B_ptr,
                                              uint32_t *result_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error = CRYS_OK;

    /* the length in words */
    uint32_t LenInWords;

    /*  indexes */
    unsigned int i, j;

    /*  variables for store carry bits by addition operations  */
    uint32_t carry, carry1;

    /*  temporary variables         */
    uint32_t temp0, temp1, temp2, temp3, temp4;

    /* FUNCTION LOGIC */

    /* initialize the lenght in words */
    LenInWords = ASizeInBits / 32;

    if (ASizeInBits % 32)

        LenInWords++;

    /*   For j from 0 to (2*size(n)*sizeof(uint32_t) do: a[j] = 0. */
    DX_PAL_MemSetZero(result_ptr, 2 * LenInWords * sizeof(uint32_t));

    /* ...................   COMPUTATION  OF MULTIPLE  ....................... */
    /* ----------------------------------------------------------------------- */

    /*  extern  loop */
    for (i = 0; i < LenInWords; i++) {
        /* carry bits from previous cicle in inner loop */
        carry1 = 0;

        /*       inner loop            */
        for (j = 0; j < LenInWords; j++) {
            /* carry bits from current cicle  */
            carry = 0;

            /* compute multiples of 16-bits halfwords of A[i] = (A1 A0) and B[j] = (B1 B0)  */
            temp0 = (A_ptr[i] & 0xFFFF) * (B_ptr[j] & 0xFFFF); /* A0*B0 */
            temp1 = (A_ptr[i] >> 16) * (B_ptr[j] & 0xFFFF);    /* A1*B0 */
            temp2 = (A_ptr[i] & 0xFFFF) * (B_ptr[j] >> 16);    /* A0*B1 */
            temp3 = (A_ptr[i] >> 16) * (B_ptr[j] >> 16);       /* A1*B1 */

            /* Remark:  The pointer A16bit_ptr will be changed in conformity with an index i of external cycle */

            /* ------------- additions  ----------------- */

            result_ptr[j] = result_ptr[j] + temp0; /* result_ptr[j] + A0*N0 */
            if (result_ptr[j] < temp0)
                carry++; /* if oweflow occurs carry = 1 */

            temp4         = result_ptr[j];
            result_ptr[j] = result_ptr[j] + (temp1 << 16); /* result_ptr[j] + low half of A0*B1 */
            if (result_ptr[j] < temp4)
                carry++; /* if oweflow occurs carry++ */

            temp4         = result_ptr[j];
            result_ptr[j] = result_ptr[j] + (temp2 << 16); /* result_ptr[j] + low byte of A1*B0 */
            if (result_ptr[j] < temp4)
                carry++; /* if oweflow occurs carry++ */

            /*  Overflow in this addition operations is impossible carry not necessary  */
            temp4 = carry1 + carry + (temp1 >> 16) + (temp2 >> 16);

            result_ptr[j + 1] = result_ptr[j + 1] + temp4; /* result_ptr[j] += carry +high bytes of A0*B1 and A1*B0 */
            if (result_ptr[j + 1] < temp4)
                carry1 = 1; /* if oweflow occurs carry1++ */
            else
                carry1 = 0;

            result_ptr[j + 1] = result_ptr[j + 1] + temp3; /* result_ptr[j] += A1*B1    */
            if (result_ptr[j + 1] < temp3)
                carry1++; /* if oweflow occurs carry1++ */

        } /* end of inner loop */

        /*  computation of pointers for next cycle */
        result_ptr = result_ptr + 1;

    } /* end of extern loop */

    return Error;

} /* END OF LLF_PKI_UTIL_ExecuteRMulOperation */
