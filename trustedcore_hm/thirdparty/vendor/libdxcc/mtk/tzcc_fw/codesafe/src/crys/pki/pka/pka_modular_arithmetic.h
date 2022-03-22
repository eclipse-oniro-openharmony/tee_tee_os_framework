/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _PKA_ModularArithmetic_H
#define _PKA_ModularArithmetic_H

#include "sasi_ecpki_types.h"
#include "pka_ecc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines *************************************** */

/* *********************** Enums ***************************************** */

typedef enum {
    CompareEqual = 0,
    FirstGrate   = 1,
    SecondGrate  = 2,

    LLF_ECPKI_CompareResultLast = 0x7FFFFFFF,

} LLF_ECPKI_CompareResult_t;

/* *********************** Typedefs ************************************* */

/* *********************** Global Data ********************************** */

/* *********************** Public functions ***************************** */

/* *************************************************************************
 *                pka_jacobi_symb()  function                 *
 * *********************************************************************** */
/*
 * Calculate Jacoby symbol for a and prime b numbers.
 *     Assumed: a, b are a positive numbers.
 *     Note: rA, rB registers are destroed by the function.
 *
 * @author reuvenl (10/26/2014)
 *
 * @param rA - A virt. pointer to PKA register, contening a.
 * @param rB - A virt. pointer to PKA register, contening b.
 *
 * @return int jacoby symbol value.
 */
int pka_jacobi_symb(void /* uint32_t rA, uint32_t rB */);

/* *************************************************************************
 *                  LLF_ECPKI_SquareRootModPrime()  function            *
 * *********************************************************************** */
/*
 * The function calculates square root modulo prime:
 *   rY1 = rY2 ^ 1/2 mod rP if root exists, else returns an error.
 *
 *   Assuming: 1. The modulus N is a prime.
 *             2. Y2 is less than modulus.
 *
 *   Implicit parameters (defined registers numbers):
 * @param rY1 - A virt. pointer to result root PKA register.
 * @param rY2 - A virt. pointer to input value PKA register.
 * @param rN  - A virt. pointer to  modulus PKA register, assumed rN = 0.
 *
 * @return int: returns 1, if the root exists, or 0 if not.
 */
int pka_mod_square_root(void /* uint32_t rY1 , const uint32_t rY2, const uint32_t rP */);

/* ********************************************************************** */

#ifdef __cplusplus
}
#endif

#endif
