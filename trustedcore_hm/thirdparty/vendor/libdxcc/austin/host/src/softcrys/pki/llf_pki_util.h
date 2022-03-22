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

#ifndef LLF__PKI_UTIL_H
#define LLF__PKI_UTIL_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "dx_pal_types.h"
#include "sw_llf_pki_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  11.06.2006
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version sw_llf_pki_error.h#1:incl:1
 *  \author adams, reuvenl
 */

/* *********************** Defines ***************************** */

/* *********************** Enums ******************************* */

/* *********************** Typedefs  *************************** */

/* *********************** Structs  **************************** */

/* the structure of the additional low level arguments for the MonMul
function , that need to be initialized once before running */
typedef struct {
    int32_t mod0tag;

} LLF_PKI_UTIL_MonMulInputParam_t;

/* type definition of pointer to Montgomery multiplication function   */

typedef void(LLF_PKI_UTIL_MonMulFunc_t)(uint32_t *, uint32_t *, uint32_t *, uint32_t, uint32_t *, uint32_t *,
                                        LLF_PKI_UTIL_MonMulInputParam_t *);

/* *********************** Public Variables ***************************** */

/* *********************** Public Functions ***************************** */

/*
 * @brief This function starts the MonMUL operation. this is the first call
 *        required when starting an MonMul session.
 *
 *
 *
 * @param[in] N_ptr - The pointer of n vector.
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t LLF_PKI_UTIL_StartMonMulOperation(uint32_t *N_ptr, LLF_PKI_UTIL_MonMulInputParam_t *LLFSpesificParams_ptr);

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
LLF_PKI_UTIL_MonMulFunc_t *LLF_PKI_UTIL_GetNameOfMonMulOp(uint32_t *mod_ptr, uint32_t ModSizeInWords);

/* ***************************************************************************************************
 *                LLF_PKI_UTIL_ExecuteMonMulOperation() function                                    *
 * ************************************************************************************************* */
/*
 * @brief This function executes the MonMUL operation.
 *
 *        The monMul operation is : A * B * (R^-1) mod n,
 *
 *        This function may have the following implementations (according to included c-file):
 *        1. ARM assembler implementation, which may works with moduls sizes which is multiple of 128
 *           bits only. This implementation is more fast and used in PKI RSA and ECPKI functions for
 *           said modulus sizes.
 *        2. C - implementation for processors with 32x32 bit multiplier (middle performance). The function
 *           may works with all sizes of modulus.
 *        3. C - implementation for processors with 16x16 bit multiplier (less performance). The function
 *           may works with all sizes of modulus.
 *
 *        The function algorithm is algorithm for Montgomery multiplication [according to A.Menesis
 *        Handbook of applied cryptography. 1977.  Algotythm 14.36] :
 *
 *        LET:
 *        mod = mod - modulo;
 *        base = 2 ^ sizeof(uint32_t) ,
 *        R = base ^ (modLen),
 *        mod0tag = - mod[0]^-1 modulo (2^32),
 *
 *
 *        ASSUMES:   1. mod > 0.
 *                   2. gcd(base, mod)) = 1.
 *                   3. 0 <= b,c <= mod
 *
 * @param[in] A_ptr - The pointer of A vector.
 * @param[in] B_ptr - The pointer of B vector.
 * @param[in] N_ptr - The pointer of n vector.
 * @param[in] ASizeInBits - The size of A vec in bits.
 * @param[in] BSizeInBits - The size of B vec in bits.
 * @param[in] NSizeInBits - The size of N vec in bits.
 * @param[out] result - the vector of the result.
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 * @param[in] prevResult_ptr -  a pointer of the previous result buffer - input to help the performance.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
void LLF_PKI_UTIL_ExecuteMonMulOperation(uint32_t *A_ptr, uint32_t *B_ptr, uint32_t *N_ptr, uint32_t NSizeInBits,
                                         uint32_t *prevResult_ptr, uint32_t *result_ptr,
                                         LLF_PKI_UTIL_MonMulInputParam_t *LLFSpesificParams_ptr);

/* ***************************************************************************************************
 *                LLF_PKI_UTIL_ExecuteMonMulOpForModNotMult128bit() function                        *
 * ************************************************************************************************* */
/*
 * @brief This function  executes the MonMUL operation for modules of any length (including not
 *        multiple of 128 bit).
 *
 *        The function contains ARM assembler for perfomance critical parts of code.
 *
 *        The monMul operation is : Result = (A * B)  mod n
 *
 *        The function is written on ARM assembler for increasing performance.
 *        This function may works with modules which are not multiple of 128 bits and used in ECPKI
 *        functions.
 *
 *        The function algorithm is algorithm of Montgomery multiplication [according to A.Menesis
 *        Handbook of applied cryptography. 1977.  Algorythm 14.36] :
 *
 *        LET:
 *
 *        mod = mod - modulo;
 *        base = 2 ^ sizeof(uint32_t) (in this case base = 2^32),
 *        R = base ^ (modLen),
 *        mod0tag = - mod[0]^-1 modulo (2^32),
 *
 *
 *        ASSUMES:   1. mod > 0.
 *                   2. gcd(base, mod)) = 1.
 *                   3. 0 <= b,c <= mod
 *
 * @param[in] A_ptr - The pointer of A vector.
 * @param[in] B_ptr - The pointer of B vector.
 * @param[in] N_ptr - The pointer of n vector.
 * @param[in] ASizeInBits - The size of A vec in bits.
 * @param[in] BSizeInBits - The size of B vec in bits.
 * @param[in] NSizeInBits - The size of N vec in bits.
 * @param[out] result - the vector of the result.
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 * @param[in] prevResult_ptr -  a pointer of the previous result buffer - input to help the performance.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
void LLF_PKI_UTIL_ExecMonMulOpForModNotMult128bit(uint32_t *A_ptr, uint32_t *B_ptr, uint32_t *N_ptr,
                                                  uint32_t NSizeInBits, uint32_t *prevResult_ptr, uint32_t *result_ptr,
                                                  LLF_PKI_UTIL_MonMulInputParam_t *LLFSpesificParams_ptr);

/* ***************************************************************************************************
 *                LLF_PKI_UTIL_ExecuteRMulOperation() function                                      *
 * ************************************************************************************************* */
/*
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
 * @param[in] ASizeInBits - The size of A vec in bits.
 * @param[out] result - the vector of the result.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t LLF_PKI_UTIL_ExecuteRMulOperation(uint32_t *A_ptr, uint32_t ASizeInBits, uint32_t *B_ptr,
                                              uint32_t *result_ptr);

/* *********************************************************************************** */
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
 *                         Its size must be 2048 + 60 bits. ( max key size + 60 bits ).
 * @Res_ptr[out]         - The pointer to the buffer that will contain the result.
 * @TempBuff2_ptr[in]    - temporary buffer
 * @Output_ptr[in,out] The output vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CRYSError_t LLF_PKI_UTIL_CalcExponent(uint32_t *Base_ptr, uint32_t BaseSizeInBits, uint32_t *Exp_ptr,
                                      uint32_t ExpSizeInBits, uint32_t *N_ptr, uint32_t NSizeInBits, uint32_t Window,
                                      uint32_t *TempBuff1_ptr, uint32_t *TempBuff2_ptr, uint32_t *Res_ptr);

/* *********************************************************************************** */
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
 * Author: Victor Elkonin
 *
 * Last Rivision: 1.00.00
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

uint32_t LLF_PKI_UTIL_digitDiv(uint32_t *b_ptr, uint32_t c);

/* *********************************************************************************** */
/*
 * ==================================================================
 * Function name: LLF_PKI_UTIL_div
 *
 * Description: This function performs a division of two big numbers.
 *
 *
 * Computes modRes = b mod n. DivRes_ptr = floor(b/n)
 * Lengths: modRes[modLen], b[numLen], c[modLen], res_ptr[numLen].
 * Assumes:
 * c > 0.
 *
 * Author: Victor Elkonin
 *
 * Last Rivision: 1.00.00
 *
 * Method: Overestimation and correction.
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

void LLF_PKI_UTIL_div(uint32_t *b_ptr, uint32_t numSizeInWords, uint32_t *n_ptr, uint32_t modSizeInWords,
                      uint32_t *modRes_ptr, uint32_t *DivRes_ptr, uint32_t *tempBuff_ptr);

/* *********************************************************************************** */
/*
 * ==================================================================
 * Function name: LLF_PKI_UTIL_InvMod
 *
 * Description: This function finds multiplicative inverse modulo prime number.
 *
 *
 *  Computes ordinary multiplicative inverse modulo prime number a=b^-1 mod p.
 *  Lengths: Result[digits], b[digits], p[digits].
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
void LLF_PKI_UTIL_InvMod(uint32_t *b, uint32_t *p, uint32_t *Result, uint32_t *temp_ptr, uint32_t digits);

/* *********************************************************************************** */
/*
 * Function name: SW_LLF_PKI_gcd
 *
 * Description: This function calculates the GCD of two numbers.
 *
 * Computes a = gcd(b, c).
 * Assumes b > c.
 *
 * Author: Victor Elkonin
 *
 * Last Rivision: 1.00.00
 *
 * Method: IEEE P1363/D13 Annex A15.1 and A15.2
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

void SW_LLF_PKI_gcd(uint32_t *b_ptr, uint32_t *c_ptr, uint32_t *result_ptr, uint32_t *temp_ptr, uint32_t len);

/* *********************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif
