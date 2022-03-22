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

/* ********************** Include Files **************8********* */

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "crys_common_math.h"
#include "sw_llf_pki_error.h"
#include "sw_llf_pki.h"
#include "sw_llf_pki_rsa.h"
#ifndef DX_SOFT_KEYGEN
#include "crys_pka_defs.h"
#endif
#include "llf_pki_util.h"

/* *********************** Defines ***************************** */

/* canceling the PC-lint warning:
   Unusual pointer cast (incompatible indirect types) */


#define GET_HALF_WORD_BIG_END(WordArray, i, HalfWord /* result */) \
    {                                                            \
        HalfWord = (WordArray)[(i) / 2];                         \
        if ((i) % 2 == 0)                                        \
            HalfWord &= 0xFFFF;                                  \
        else                                                     \
            HalfWord = HalfWord >> 16;                           \
    }

/* *********************** Enums ******************************* */

/* *********************** Typedefs **************************** */

/* *********************** Global Data ************************* */

/* ************ private service function *********************** */

/* ************ Exported function prototype ******************** */

/*
 * @brief The LLF_PKI_UTIL_CalcExponent calculates The following:
 *
 *                   res = (Base ^ exp) mod N.
 *
 *                   using Montgomery representations.
 *
 * Assumes:
 * 1. (mod) > 0, powerLen > 0,
 * According to Handbook of Applied Cryptography, Menezes et. al.14.94
 * combined with sliding-window exponentiation 14.85 .
 *
 *
 *
 * @Base_ptr[in]         - The pointer to the base buffer.
 * @BaseSizeInBits[in]   - The size of the base value in bits.
 * @Exp_ptr[in]          - The pointer to the exponent buffer.
 * @ExpSizeInBits[in]    - The size of the exponent in bits.
 * @N_ptr[in]            - The pointer to the modulus buffer.
 * @NSizeInBits[in]      - The modulus size in bits.
 * @TempBuff1_ptr[in]    - temporary buffer.
 *                         It's size must be 34 max key size .
 * @Res_ptr[out]         - The pointer to the buffer that will contain the result.
 * @TempBuff2_ptr[in]    - temporary buffer. It's size must be 2 max modulus size.
 * @Output_ptr[in,out] The output vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t LLF_PKI_UTIL_CalcExponent(uint32_t *Base_ptr, uint32_t BaseSizeInBits, uint32_t *Exp_ptr,
                                      uint32_t ExpSizeInBits, uint32_t *N_ptr, uint32_t NSizeInBits, uint32_t Window,
                                      uint32_t *TempBuff1_ptr, /* big buffer for exp */
                                      uint32_t *TempBuff2_ptr, /* 2 max mod size */
                                      uint32_t *Res_ptr)
{
    /* LOCAL DECLERATIONS */

    /* the error identifier */
    CRYSError_t Error;

    /* the MMUL operation data base handle */
    LLF_PKI_UTIL_MonMulInputParam_t LLFSpesificParams_ptr;

    /* Pointer to Montgomery multiplication function */
    LLF_PKI_UTIL_MonMulFunc_t *ExecuteMonMulOperation_func;

    /* other local variables */
    uint32_t i;
    int32_t i1;
    uint32_t tempBits1;
    uint32_t L;
    uint32_t slidingWindow1;
    uint32_t k      = Window;
    uint32_t powers = 1 << (k - 1);
    uint32_t tempOne0;
#ifdef BIG__ENDIAN
    uint32_t tempOne1;
#endif
    uint32_t LeftBitOne1 = (1 << (16 + k - 1));
    uint32_t maskWindow1 = ((uint16_t)((1 << k) - 1) << 16);
    uint32_t len;
    uint32_t powerLen;
    uint32_t *base2_ptr;
    uint32_t *pSpace_ptr = TempBuff1_ptr;

    /* short pointer on powers   */
#ifndef BIG__ENDIAN
    uint16_t *halfPower_ptr = (uint16_t *)Exp_ptr;
#endif

    /* FUNCTION LOGIC */

    /* ........................ initialize the local variables ............... */
    /* ----------------------------------------------------------------------- */

    /* to avoid compilers warnings */
    BaseSizeInBits = BaseSizeInBits;

    Error = CRYS_OK;

    len = NSizeInBits / 32;

    if (NSizeInBits % 32)

        len++;

    powerLen = ExpSizeInBits / 32;

    if (ExpSizeInBits % 32)

        powerLen++;

    /* get pointer to appropriate Montgomery multiplication function according to
       that is the len multiple of 4 words or not   */
    ExecuteMonMulOperation_func = LLF_PKI_UTIL_GetNameOfMonMulOp(N_ptr, len);

    base2_ptr = TempBuff1_ptr + (powers - 1) * len;

    /* calculate base of exponentiation in the Montgomery representation: */

    DX_PAL_MemSetZero(TempBuff1_ptr + len, len * sizeof(uint32_t));
    DX_PAL_MemCopy(TempBuff1_ptr + 2 * len, Base_ptr, len * sizeof(uint32_t));

    LLF_PKI_UTIL_div(TempBuff1_ptr + len, 2 * len, /* numerator - in */
                     N_ptr, len,                   /* modulus - in */
                     TempBuff1_ptr,                /* modulus result - in */
                     TempBuff1_ptr + 3 * len,      /* div result - in */
                     TempBuff1_ptr + 5 * len);     /* temporary buffer - in */

    /* precomputation  powers of base: */

    /* calculate  mod0tag (LLFSpesificParameter)  -
       start the MMUL operation with vectors Base & Module */
    LLF_PKI_UTIL_StartMonMulOperation(N_ptr, &LLFSpesificParams_ptr);

    /*  1.  base2 = base*base */
    if (Window > 1)

        ExecuteMonMulOperation_func(TempBuff1_ptr, TempBuff1_ptr, N_ptr, NSizeInBits, TempBuff2_ptr, base2_ptr,
                                    &LLFSpesificParams_ptr);

    /* 2. the odd powers of the base: */
    for (i = 1; i < powers; i++) {
        ExecuteMonMulOperation_func(pSpace_ptr, base2_ptr, N_ptr, NSizeInBits, TempBuff2_ptr, pSpace_ptr + len,
                                    &LLFSpesificParams_ptr);
        pSpace_ptr += len;
    }

    /* index i1 for pointer of half words of power */
    i1 = (int32_t)(2 * (powerLen - 1));

#ifndef BIG__ENDIAN
    tempOne0 = halfPower_ptr[i1 + 1];
#else
    GET_HALF_WORD_BIG_END(Exp_ptr, i1 + 1, tempOne0);
#endif

    if (tempOne0 != 0)
        i1 += 1; /* if high half of MSD != 0    */

    /* ---------- do exponentiation  ------------------ */

    /* in first iteration *result = *base */
    DX_PAL_MemCopy(Res_ptr, TempBuff1_ptr, len * sizeof(uint32_t));

    tempBits1 = 16; /* value of bits in half word */

#ifndef BIG__ENDIAN
    tempOne0 = (((uint32_t)(halfPower_ptr[i1])) << k);
#else
    GET_HALF_WORD_BIG_END(Exp_ptr, i1, tempOne0);

    tempOne0 = tempOne0 << k;
#endif

    /* scan most non zero bit of most significant 16-bits word: */
    while (!(tempOne0 & LeftBitOne1)) {
        tempOne0 <<= 1;
        tempBits1 -= 1;
    }

    /* shift to first bit after finding most significant non zero bit */
    tempOne0 <<= 1;
    tempBits1 -= 1;

    /* ---------  extern loop of exponentiation /step by half digits ----- */
    while (i1 >= 0) {
        /* inner loop /step by bits */
        while (tempBits1 > 0) {
            /* if left bit tested is 0, then result= result*result */
            if (!(tempOne0 & LeftBitOne1)) {
                ExecuteMonMulOperation_func(Res_ptr, Res_ptr, N_ptr, NSizeInBits, TempBuff2_ptr, Res_ptr,
                                            &LLFSpesificParams_ptr);

                tempOne0 <<= 1; /* shift to next bit */
                tempBits1--;
            }

            /* if left bit tested is 1 - exponentiation in sliding-window */
            else {
                if (tempBits1 >= k)
                /* slidingWindow can be placed in the current half digit of exp->power */
                {
                    /* cut */
                    slidingWindow1 = (uint32_t)((tempOne0 & maskWindow1) >> (16 + Window - k));

                    L = k; /* number bits in sliding- window */

                    while (!(slidingWindow1 & 1)) {
                        slidingWindow1 >>= 1; /* count and treat all right zero bits of slidingWindow */
                        L--;
                    }
                    tempOne0 <<= L; /* shift  on number of bits in slidingWindow */
                    tempBits1 -= L;

                    while (L) { /* consequently squaring L times */
                        ExecuteMonMulOperation_func(Res_ptr, Res_ptr, N_ptr, NSizeInBits, TempBuff2_ptr, Res_ptr,
                                                    &LLFSpesificParams_ptr);
                        L--;
                    }

                    ExecuteMonMulOperation_func(Res_ptr, TempBuff1_ptr + len * (slidingWindow1 - 1) / 2, N_ptr,
                                                NSizeInBits, TempBuff2_ptr, Res_ptr, &LLFSpesificParams_ptr);
                } else
                /* slidingWindow k-bits can not be placed, reduce k */
                {
                    if (i1 > 0)
                        break;
                    else
                        k--;
                }

            } /* end else if(!(tempOne0 & LeftBitOne1)) */

        } /* end while(tempBits1 > 0) */

        if (i1-- > 0) {
            /* Load the next half digit of the power: */
#ifndef BIG__ENDIAN
            tempOne0 |= ((uint32_t)(halfPower_ptr[i1]) << (k - tempBits1));
#else
            GET_HALF_WORD_BIG_END(Exp_ptr, i1, tempOne1);

            tempOne0 |= tempOne1 << (k - tempBits1);
#endif

            tempBits1 += 16;
        }

    } /* end while(i >= 0) */

    /* transform the result into regular representation on end of process: */

    DX_PAL_MemSetZero(TempBuff1_ptr, len * sizeof(uint32_t));
    TempBuff1_ptr[0] = 1;

    ExecuteMonMulOperation_func(Res_ptr, TempBuff1_ptr, N_ptr, NSizeInBits, TempBuff2_ptr, Res_ptr,
                                &LLFSpesificParams_ptr);

    /* ............... end of the function .................. */
    /* ------------------------------------------------------ */

    return Error;

} /* END OF LLF_PKI_UTIL_CalcExponent */
