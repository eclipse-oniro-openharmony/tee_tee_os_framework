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

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* ************ Function prototypes ************** */

/* ***************************************************************************************************
 *                LLF_PKI_UTIL_GetNameOfMonMulOp() function                                         *
 * ************************************************************************************************* */
/*
 * @brief  The function checks modulus and returns pointer to appropriate MonMult function,
 *         which may works with this modulus.
 *
 * @param[in] mod_ptr  - A pointer to modulus.
 * @param[in] ModSizeInWords - The modulus size in words
 * @return  - Pointer of type LLF_PKI_UTIL_MonMulFunc_t*  to MonMult function.
 *
 */
LLF_PKI_UTIL_MonMulFunc_t *LLF_PKI_UTIL_GetNameOfMonMulOp(uint32_t *mod_ptr, uint32_t ModSizeInWords)
{
    /* preventing compiler warnings */
    mod_ptr        = mod_ptr;
    ModSizeInWords = ModSizeInWords;

    return &LLF_PKI_UTIL_ExecuteMonMulOperation;
}

/*
 * @brief This function starts the MonMUL operation. this is the first call
 *        required when starting an MonMul session.
 *
 *        The monMul operation is : (A * B) mod n
 *
 *        Autor Victor Elkonin
 * @param[in] N_ptr - The pointer of n vector.
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t LLF_PKI_UTIL_StartMonMulOperation(uint32_t *N_ptr, LLF_PKI_UTIL_MonMulInputParam_t *LLFSpesificParams_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    int32_t i;
    uint32_t C = 0;
    uint32_t D = 0xffffffff;

    /* FUNCTION LOGIC */

    /* initialize the ERROR to O.K */
    Error = CRYS_OK;

    /* Binary extended Euclidean Algorithm for multiplicative inverse:
       For input odd digit N_ptr[0] find digit b such that a*b=1 mod 2^32. */

    /* find the invers of the first word of the modulus */
    for (i = 0; i < 32; i++) {
        C >>= 1;
        if (D & 1) {
            D += N_ptr[0];

            C += 0x80000000;
        }

        D >>= 1;
    }

    /* set the r0 tag as the inverse of the first value of the modulus */
    LLFSpesificParams_ptr->mod0tag = -(int32_t)C;

    return Error;

} /* END OF LLF_PKI_StartMonMulOperation */

/* ***************************************************************************************************
 *                LLF_PKI_UTIL_ExecuteMonMulOperation() function                                *
 * ************************************************************************************************* */
/*
 * @brief This function executes the Montgomery Multiplication operation.
 *
 *        Result = (A * B) * R^-1 mod N.
 *
 *        This file includes the following implementation of the function:
 *           C - implementation for processors with 32x32 bit multiplier and 64 bits result.
 *           The function may works with different sizes of modulus and used in RSA and ECPKI operations.
 *
 *        The function algorithm (according to A.Menesis, Handbook of applied cryptography. 1977. Algorithm 14.36]):
 *
 *        LET:
 *             N - modulus;
 *             base =  2^32,
 *             R = base ^ (modLenInWords),
 *             mod0tag = - mod [0] ^-1 mod base,
 *
 *        THEN:  Result = (A * B) * R^-1 mod N.
 *
 *        ASSUMES:   1. N > 0.
 *                   2. gcd(base, N) = 1.
 *                   3. 0 <= A, B <= N
 *
 * @param[in] A_ptr - The pointer of A vector.
 * @param[in] B_ptr - The pointer of B vector.
 * @param[in] N_ptr - The pointer of n vector.
 * @param[in] ASizeInBits - The size of A vector in bits.
 * @param[in] BSizeInBits - The size of B vector in bits.
 * @param[in] NSizeInBits - The size of N vector in bits.
 * @param[out] result - the vector of the result.
 * @param[in] LLFSpesificParams - specific parameter (mod0tag) required on this LLF implementation.
 * @param[in] prevResult_ptr -  a pointer of the previous result buffer - input to help the performance.
 *
 * @return  - no return value.
 */
void LLF_PKI_UTIL_ExecuteMonMulOperation(uint32_t *A_ptr, uint32_t *B_ptr, uint32_t *N_ptr, uint32_t NSizeInBits,
                                         uint32_t *prevResult_ptr, uint32_t *result_ptr,
                                         LLF_PKI_UTIL_MonMulInputParam_t *LLFSpesificParams_ptr)

{
    /* LOCAL DECLERATIONS */

    /* the input buffers pointers and indexes */
    uint32_t *mod_ptr;
    uint32_t digits, digits_1;

    uint32_t *res_ptr;
    uint32_t mod0tag;

    int32_t i;
    register uint32_t j;

    uint32_t carry;
    register uint32_t temp0, res0, res1;
    register uint32_t u;
    uint64_t res_0, Ai;

    /* FUNCTION LOGIC */

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* set the popinter to the modulus buffer */
    mod_ptr = N_ptr;

    /* set the modulus lenght in words */
    digits   = (NSizeInBits + 31) / 32;
    digits_1 = digits - 1;

    /* set the mon mul factor from the mmul database */
    mod0tag = (uint32_t)LLFSpesificParams_ptr->mod0tag;

    /* set the temp buffer */

    res_ptr = prevResult_ptr;
    DX_PAL_MemSetZero(res_ptr, digits * sizeof(uint32_t));
    res_ptr[digits] = 0;

    /* ................ execute the MonMult .................... */
    /* --------------------------------------------------------- */
    for (i = 0; i < (int32_t)digits; i++) {
        /* Calculate   u    */
        Ai = *A_ptr;
        u  = mod0tag * (*res_ptr + (uint32_t)Ai * (*B_ptr));

        /* internal loop variables initialization */

        res_0 = 0;
        res0  = 0;
        res1  = 0;
        carry = 0;

        j = digits_1;

        do { /* internal loop begin */
            /* In each cycle calculated:
             * (*result, *(result+1)) += (*A_ptr *  *B_ptr++) + (u *  *mod_ptr++)
             * and carry stored to next *result
             */
            res_0 = Ai * (*B_ptr++) + res0;
            res0  = (uint32_t)res_0;                /* res0 = (Low half of res_0) */
            res1  = res1 + (uint32_t)(res_0 >> 32); /* res1 + (High half of res_0) */
            if (res1 < carry)
                carry = 1;
            else
                carry = 0;

            res_0 = (uint64_t)u * (*mod_ptr++) + res0;
            temp0 = res1;
            res0  = (uint32_t)res_0;                /* res0 = (Low half of res_0) */
            res1  = res1 + (uint32_t)(res_0 >> 32); /* res1 + (High half of res_0) */
            if (res1 < temp0)
                carry++;

            temp0    = *res_ptr;
            *res_ptr = *res_ptr + res0;
            res0     = res1;

            if (temp0 > *res_ptr)
                res0++;
            if (res0 < res1)
                carry++;
            res_ptr++;
            res1 = carry;

        } while (j-- != 0); /* end internal loop  */

        /* Last result digit calculation */
        temp0    = *res_ptr;
        *res_ptr = *res_ptr + res0;
        if (temp0 > *res_ptr)
            res1++;
        res_ptr++;
        *res_ptr = res1;

        /* Initialization of indices for next cicle of intrnal loop */
        B_ptr -= digits;
        mod_ptr -= digits;
        res_ptr -= digits;
        A_ptr++;

    } /* end external loop */

    /* Check if result is bigger that mod: */
    if (res_ptr[digits] == 0) {
        while (i--) { /* mod and result are different */
            if (res_ptr[i] > mod_ptr[i])
                goto Subtract;
            if (mod_ptr[i] > res_ptr[i])
                goto Finish;
        }
    }

Subtract: /* In case result is greater than modulus - subtract modulus from result */

    carry = 0;
    for (j = 0; j < digits; j++) {
        temp0      = res_ptr[j];
        res_ptr[j] = res_ptr[j] - carry;

        if (res_ptr[j] > temp0)
            carry = 1;
        else
            carry = 0;

        temp0      = res_ptr[j];
        res_ptr[j] = res_ptr[j] - *mod_ptr++;
        if (res_ptr[j] > temp0)
            carry++;
    }

Finish:

    if (res_ptr != result_ptr) {
        DX_PAL_MemCopy(result_ptr, res_ptr, digits * sizeof(uint32_t));
    }

    return;

} /* END OF LLF_PKI_UTIL_ExecuteMonMulOperation */
