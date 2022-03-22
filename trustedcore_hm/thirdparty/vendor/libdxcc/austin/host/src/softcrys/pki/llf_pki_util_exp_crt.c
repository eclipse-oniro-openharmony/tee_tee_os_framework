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

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Wed Nov 17 17:39:24 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version llf_pki_util_exp_crt.c#1:csrc:1
 *  \author adams
 */

/* ********************** Include Files **************8********* */

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "crys_common_math.h"
#include "crys_rnd.h"
#include "sw_llf_pki_error.h"
#include "sw_llf_pki.h"
#ifndef DX_SOFT_KEYGEN
#include "crys_pka_defs.h"
#endif
#include "llf_pki_util.h"
#include "sw_llf_pki_rsa.h"

/* *********************** Defines ***************************** */

/* canceling the PC-lint warning:
   Unusual pointer cast (incompatible indirect types) */


/* *********************** Enums ******************************* */

/* *********************** Typedefs **************************** */
/* *********************** Global Data ************************* */

/* ************ private service function *********************** */

/* ************ Exported function prototype ******************** */

/* ************************************************************************** */
/*
 * @brief The LLF_PKI_UTIL_CalcExponentCrt calculates The exponent on the CRT mode.
 *        it does the following:
 *
 *                   m1 = (Base ^ dP) mod P.
 *                   m2 = (Base ^ dQ) mod Q.
 *                   h = (m1 - m2) * Qinv mod P
 *                   res = m2 + qh
 *
 * @Base_ptr[in]         - The pointer to the base buffer.
 * @BaseSizeInBits[in]   - The size of the base value in bits.
 * @N_ptr[in]            - The pointer to the modulus buffer.
 * @NSizeInBits[in]      - The modulus size in bits.
 * @P_ptr[in]            - The pointer to the first factor buffer.
 * @PSizeInBits          - The first factor size in bits.
 * @Q_ptr[in]            - The pointer to the second factor buffer.
 * @QSizeInBits          - The second factor size in bits.
 * @Qinv_ptr             - The pointer to the coefficient.
 * @QinvSizeInBits       - The coefficient size in bits.
 * @TempBuff1_ptr[in]    - temporary buffer
 * @TempBuff2_ptr[in]    - temporary buffer
 * @Res_ptr[out]         - The pointer to the buffer that will contain the result.
 *
 * @Output_ptr[in,out] The output vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t LLF_PKI_UTIL_CalcExponentCrt(uint32_t *Base_ptr, uint32_t BaseSizeInBits, uint32_t *N_ptr,
                                         uint32_t NSizeInBits, uint32_t *P_ptr, uint32_t PSizeInBits, uint32_t *Q_ptr,
                                         uint32_t QSizeInBits, uint32_t *dP_ptr, uint32_t dPSizeInBits,
                                         uint32_t *dQ_ptr, uint32_t dQSizeInBits, uint32_t *Qinv_ptr,
                                         uint32_t QinvSizeInBits, uint32_t *TempBuff1_ptr, uint32_t *TempBuff2_ptr,
                                         uint32_t *Res_ptr)
{
    /* LOCAL DECLARATIONS */

    /* the error identifier */
    CRYSError_t Error;

    uint32_t digits;
    uint32_t digits2;
    uint32_t borrow;
    uint32_t j;
    uint32_t *u_ptr;
    uint32_t *v1_ptr;
    uint32_t *v2_ptr;
    uint32_t *dummy_ptr;
    uint32_t *v2Minusv1_ptr;
    uint32_t sumL, sumH, temp;
    uint32_t Window;

    /* FUNCTION LOGIC */

    /* ........................ initialize the local variables ............... */
    /* ----------------------------------------------------------------------- */

    /* to avoid compilers warnings - parameters not in use */
    N_ptr          = N_ptr;
    QinvSizeInBits = QinvSizeInBits;

    /* initialize the error identifier to O.K */
    Error = CRYS_OK;

    /* set the digits len in words */
    digits = NSizeInBits / 32;

    if (NSizeInBits % 32)

        digits++;

    digits2 = digits >> 1;

    /* initialize the window for the exponents */
    if (digits > 80)
        Window = 6;
    else
        Window = 5;

    /* check that window is not great than the defined maximal value */
    if (Window > PKI_EXP_SLIDING_WINDOW_MAX_VALUE)

        Window = PKI_EXP_SLIDING_WINDOW_MAX_VALUE;

    /* setting the temporary buffers pointers using the big TempBuff1_ptr buffer */
    v1_ptr        = TempBuff1_ptr;
    v2_ptr        = v1_ptr + digits2;
    u_ptr         = v2_ptr + digits2;
    v2Minusv1_ptr = u_ptr;

    /* set the dummpy pointer for the div and the exponent */
    dummy_ptr = TempBuff1_ptr + 3 * digits + 1 + 1;

    /* Init v1 with data(base) mod Q */
    LLF_PKI_UTIL_div(Base_ptr, digits, /* numerator - in */
                     Q_ptr, digits2,   /* modolus - in */
                     v1_ptr,           /* modulous result - in */
                     dummy_ptr,        /* div result - in */
                     u_ptr + digits2); /* temporary buffer - in */

    /* Init v2 with data(base) mod P */
    LLF_PKI_UTIL_div(Base_ptr, digits, /* numerator - in */
                     P_ptr, digits2,   /* modolus - in */
                     v2_ptr,           /* modulous result - in */
                     dummy_ptr,        /* div result - in */
                     u_ptr + digits2); /* temporary buffer - in */

    /* calculate v1 = v1 ^ dQ mode Q */
    LLF_PKI_UTIL_CalcExponent(v1_ptr, BaseSizeInBits, dQ_ptr, dQSizeInBits, Q_ptr, QSizeInBits, Window, dummy_ptr,
                              TempBuff2_ptr, v1_ptr);

    /* calculate v2 = v2 ^ dP mode P */
    LLF_PKI_UTIL_CalcExponent(v2_ptr, BaseSizeInBits, dP_ptr, dPSizeInBits, P_ptr, PSizeInBits, Window, dummy_ptr,
                              TempBuff2_ptr, v2_ptr);

    /* compute ( v2 - v1 ) mod P */
    /* 1. compute ( v2 - v1 ) and borrow from subtraction */
    borrow = CRYS_COMMON_SubtractUintArrays(v2_ptr /* A_ptr */, v1_ptr /* B_ptr */, digits2 /* SizeInWords */,
                                            v2Minusv1_ptr /* Res_ptr */);
    /* 2. add P till borrow != 0 for modulo operation */
    while (borrow != 0) {
        borrow -= CRYS_COMMON_Add2vectors(v2Minusv1_ptr, P_ptr, digits2 /* SizeInWords */, v2Minusv1_ptr);
    }

    /* calculate u=((v2-v1)*(p^-1)) mod P */
    LLF_PKI_UTIL_ExecuteRMulOperation(v2Minusv1_ptr, PSizeInBits, Qinv_ptr, dummy_ptr + digits);

    /* Init v2 with data(base) mod P */
    LLF_PKI_UTIL_div(dummy_ptr + digits, digits, /* numerator - in */
                     P_ptr, digits2,             /* modolus - in */
                     u_ptr,                      /* modulous result - in */
                     dummy_ptr,                  /* div result - in */
                     u_ptr + digits2);           /* temporary buffer - in */

    /* calculate u * Q - the result is in Res_ptr */
    LLF_PKI_UTIL_ExecuteRMulOperation(u_ptr, QSizeInBits, Q_ptr, Res_ptr);

    sumL = 0;
    sumH = 0;

    for (j = 0; j < digits2; j++) {
        /* shifting the 64 bit sum reg 32 bits right */
        sumL = sumH;
        sumH = 0;

        temp = sumL;
        sumL += v1_ptr[j];
        if (sumL < temp)
            sumH += 1;

        temp = sumL;
        sumL += Res_ptr[j];
        if (sumL < temp)
            sumH += 1;

        Res_ptr[j] = sumL;
    }

    for (; j < digits; j++) {
        /* shifting the 64 bit sum reg 32 bits right */
        sumL = sumH;
        sumH = 0;

        temp = sumL;
        sumL += Res_ptr[j];
        if (sumL < temp)
            sumH += 1;

        Res_ptr[j] = sumL;
    }

    return Error;

} /* END OF LLF_PKI_UTIL_CalcExponentCrt */
